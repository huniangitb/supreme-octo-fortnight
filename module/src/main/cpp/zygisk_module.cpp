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
#include <cerrno>
#include <poll.h>

#include "zygisk.hpp"
#include "dobby.h" 

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局状态 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};
static std::atomic<bool> g_hooks_active(false);

// --- 原始函数指针 (由 Dobby 回填) ---
static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

// --- 日志系统 ---
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
    // 硬编码规则
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    
    // 动态规则
    if (g_block_rules.empty()) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- 代理函数 (Proxy Functions) ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Hook 安装逻辑 (Dobby) ---
static bool install_hooks() {
    z_log("正在使用 Dobby 初始化 Hooks...");

    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat || !sym_mkdirat) {
        if (!sym_openat) sym_openat = DobbySymbolResolver(nullptr, "openat");
        if (!sym_mkdirat) sym_mkdirat = DobbySymbolResolver(nullptr, "mkdirat");
    }

    if (!sym_openat || !sym_mkdirat) {
        z_log("致命错误：无法解析 openat 或 mkdirat 符号地址");
        return false;
    }

    int ret_open = DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
    int ret_mkdir = DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);

    if (ret_open == 0 && ret_mkdir == 0) {
        z_log("Dobby Hook 安装成功！");
        return true;
    } else {
        z_log("Dobby Hook 安装失败: open_ret=%d, mkdir_ret=%d", ret_open, ret_mkdir);
        return false;
    }
}

// --- 异步工作线程 ---
static void async_setup_thread() {
    usleep(100000); 

    if (install_hooks()) {
        g_hooks_active = true;
    }

    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            sleep(5);
            continue;
        }

        // 1. 发送握手请求
        if (write(fd, "PROXY_CONNECT", 14) <= 0) { 
            close(fd); sleep(1); continue; 
        }
        
        // 2. [修复] 等待 Companion 的 ACK 确认
        // 这确保了 Companion 已经建立了与后端的连接，并且处于转发模式
        char ack_buf[16] = {0};
        if (read(fd, ack_buf, sizeof(ack_buf)) <= 0 || strcmp(ack_buf, "OK") != 0) {
            z_log("Companion 握手失败或未收到 ACK");
            close(fd); sleep(1); continue;
        }

        // 3. 安全发送 REPORT
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        if (write(fd, report, strlen(report)) <= 0) { 
            close(fd); sleep(1); continue; 
        }

        // 4. 读取规则
        char buf[8192];
        ssize_t len;
        while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[len] = 0;
            if (strncmp(buf, "SET_RULES:", 10) == 0) {
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                g_block_rules.clear();
                char* data = buf + 10; 
                char* token = strtok(data, ",");
                while (token) {
                    if (*token) g_block_rules.emplace_back(token);
                    token = strtok(nullptr, ",");
                }
                z_log("规则更新: %zu 条", g_block_rules.size());
            }
        }
        close(fd);
        sleep(5);
    }
}

// --- Companion 逻辑 (Root 进程) ---
static void companion_proxy_bridge(int client_fd, int target_fd) {
    struct pollfd fds[2];
    fds[0].fd = client_fd; fds[0].events = POLLIN;
    fds[1].fd = target_fd; fds[1].events = POLLIN;
    char buffer[4096];

    while (poll(fds, 2, -1) > 0) {
        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & POLLIN) {
                int source = fds[i].fd;
                int dest = (i == 0) ? target_fd : client_fd;
                ssize_t n = read(source, buffer, sizeof(buffer));
                if (n <= 0 || write(dest, buffer, n) != n) goto end_bridge;
            }
            if (fds[i].revents & (POLLHUP | POLLERR)) goto end_bridge;
        }
    }
end_bridge:
    close(client_fd);
    close(target_fd);
}

static void companion_handler(int client_fd) {
    char buf[64] = {0};
    // 读取握手包
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) { close(client_fd); return; }

    if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr = {0}; // 使用 C++ 写法初始化
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            // 连接后端失败
            close(target_fd); 
            close(client_fd); 
            return;
        }

        // [修复] 关键点：向 Client 发送 ACK
        // 告诉 Client 我们已经连接好后端了，现在开始转发
        if (write(client_fd, "OK", 3) != 3) {
            close(target_fd);
            close(client_fd);
            return;
        }

        // 进入透明转发模式
        companion_proxy_bridge(client_fd, target_fd);
    } else {
        close(client_fd);
    }
}

// --- Zygisk 模块入口 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { g_api = api; this->env = env; }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name && (
            strstr(nice_name, "android.providers.media") || 
            strstr(nice_name, "android.process.media") ||
            strcmp(nice_name, "com.android.providers.media.module") == 0
        )) {
            g_is_media_process = true; 
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }
        
        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) { 
            g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); 
            return; 
        }
        
        // 启动异步线程
        std::thread(async_setup_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)