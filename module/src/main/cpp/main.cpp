FILENAME: zygisk_module.cpp
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <fcntl.h>
#include <dlfcn.h>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <android/log.h>
#include <android/dlext.h>
#include <cerrno>
#include <poll.h>

#include "zygisk.hpp"
#include "shadowhook.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 用户指定的测试路径 ---
#ifdef __aarch64__
#define TEST_LIB_PATH "/data/local/tmp/lib/abi/arm64-v8a/libshadowhook.so"
#else
#define TEST_LIB_PATH "/data/local/tmp/lib/abi/armeabi-v7a/libshadowhook.so"
#endif

static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};
static std::atomic<bool> g_hooks_active(false);

static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

// --- 路径拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    if (g_block_rules.empty()) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) if (strstr(path, prefix.c_str())) return true;
    return false;
}

// --- Hook 回调 ---
typedef int (*openat_t)(int, const char*, int, mode_t); static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) { errno = ENOENT; return -1; }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}
typedef int (*mkdirat_t)(int, const char*, mode_t); static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) { errno = EACCES; return -1; }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 尝试直接加载 Hook (不通过 Companion FD) ---
static void try_direct_load() {
    z_log("尝试直接加载 Hook 库: %s", TEST_LIB_PATH);
    
    // 尝试直接 dlopen
    // 注意：在 Android N+ 上，从 /data/local/tmp 加载可能会因为 namespace 限制被拒绝
    // 除非你 setenforce 0 并且环境允许
    void* handle = dlopen(TEST_LIB_PATH, RTLD_NOW);
    
    if (!handle) {
        z_log("直接 dlopen 失败: %s", dlerror());
        z_log("跳过 Hook 加载，继续测试 IPC 通讯...");
        return; 
    }

    auto sh_init = (int (*)(int, bool))dlsym(handle, "shadowhook_init");
    auto sh_hook = (void* (*)(const char*, const char*, void*, void**))dlsym(handle, "shadowhook_hook_sym_name");

    if (sh_init && sh_hook) {
        if (sh_init(SHADOWHOOK_MODE_UNIQUE, false) == 0) {
            orig_openat = sh_hook("libc.so", "openat", (void*)my_openat, nullptr);
            orig_mkdirat = sh_hook("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
            if (orig_openat) {
                z_log("Hook 加载成功!");
                g_hooks_active = true;
            } else {
                z_log("ShadowHook 符号查找成功但 Hook 失败");
            }
        } else {
            z_log("ShadowHook 初始化失败");
        }
    } else {
        z_log("找不到 ShadowHook 符号");
    }
}

// --- 异步工作线程 ---
static void async_setup_thread() {
    sleep(1); 

    // 1. 尝试直接加载 Hook (即使失败也继续)
    try_direct_load();

    // 2. 循环测试 IPC (核心目标)
    z_log("开始连接 Injector IPC...");
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) { 
            // 如果这里还报错，说明 Companion 进程本身有问题，或者 Zygisk 拒绝服务
            // 改为仅仅打印，不退出，等待重试
            z_log("连接 Companion 失败，5秒后重试...");
            sleep(5); 
            continue; 
        }

        // 发送 IPC 代理请求
        if (write(fd, "PROXY_CONNECT", 14) <= 0) { 
            z_log("发送 PROXY_CONNECT 失败");
            close(fd); sleep(1); continue; 
        }
        
        // 发送上报信息
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        if (write(fd, report, strlen(report)) <= 0) { 
            z_log("发送 REPORT 失败");
            close(fd); sleep(1); continue; 
        }
        
        z_log("IPC 连接建立，等待规则...");

        char buf[8192]; ssize_t len;
        while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[len] = 0;
            if (strncmp(buf, "SET_RULES:", 10) == 0) {
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                g_block_rules.clear();
                char* data = buf + 10; char* token = strtok(data, ",");
                int count = 0;
                while (token) { 
                    if (*token) { g_block_rules.emplace_back(token); count++; }
                    token = strtok(nullptr, ","); 
                }
                z_log("收到 Injector 下发的规则: %d 条", count);
            } else if (strcmp(buf, "OK") == 0) {
                 z_log("收到 Injector 心跳/确认: OK");
            } else {
                 z_log("收到未知数据: %s", buf);
            }
        }
        
        z_log("IPC 连接断开，10秒后重连...");
        close(fd);
        sleep(10);
    }
}

// --- Companion 代理桥接 (单线程 poll 实现) ---
static void companion_proxy_bridge(int client_fd, int target_fd) {
    struct pollfd fds[2];
    fds[0].fd = client_fd; fds[0].events = POLLIN;
    fds[1].fd = target_fd; fds[1].events = POLLIN;
    char buffer[4096];

    while (true) {
        if (poll(fds, 2, -1) <= 0) break;
        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & POLLIN) {
                int dest = (i == 0) ? target_fd : client_fd;
                ssize_t n = read(fds[i].fd, buffer, sizeof(buffer));
                if (n <= 0 || write(dest, buffer, n) != n) goto end;
            }
            if (fds[i].revents & (POLLHUP | POLLERR)) goto end;
        }
    }
end:
    close(client_fd); close(target_fd);
}

// --- Companion 处理 ---
static void companion_handler(int client_fd) {
    char buf[64] = {0};
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) { close(client_fd); return; }

    // 注意：我们移除了 GET_SH_FD 的处理，因为我们在 App 进程尝试直接加载
    // 如果你还需要 FD 加载，必须把 GET_SH_FD 加回来，并把路径改成 TEST_LIB_PATH

    if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            // 连接 Injector 失败
            write(client_fd, "ERR_CONN_INJECTOR", 17); // 通知客户端
            close(target_fd); close(client_fd); return;
        }
        companion_proxy_bridge(client_fd, target_fd);
    } else {
        close(client_fd);
    }
}

class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { g_api = api; this->env = env; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (nice_name && (strstr(nice_name, "android.providers.media") || strstr(nice_name, "android.process.media"))) {
            g_is_media_process = true; strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }
        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) { g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); return; }
        if (g_api) std::thread(async_setup_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)