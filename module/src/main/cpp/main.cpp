#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
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
#include <android/log.h>
#include <libgen.h>

#include "zygisk.hpp"
#include "shadowhook.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {0};

// --- 日志系统 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    // 强制输出 PID 和 进程名 标签
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[PID:%d][%s] %s", getpid(), g_process_name[0] ? g_process_name : "zygote", msg);
}

// --- 路径匹配逻辑 ---
static bool is_media_blocked(const char* path) {
    if (!path || path[0] != '/') return false;
    
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    if (g_block_rules.empty()) return false;

    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 函数定义 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_media_blocked(path)) {
        z_log("拦截(openat): %s", path);
        errno = ENOENT; 
        return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_media_blocked(path)) {
        z_log("拦截(mkdirat): %s", path);
        errno = EACCES; 
        return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 动态规则解析 ---
static void update_rules(const char* msg) {
    if (strncmp(msg, "SET_RULES:", 10) != 0) return;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    
    // 保留硬编码规则，不被清空
    g_block_rules.clear();
    g_block_rules.emplace_back("/storage/emulated/0/Download/1DMP"); 

    char* data = strdup(msg + 10);
    char* token = strtok(data, ",");
    while (token) {
        if (strlen(token) > 0) g_block_rules.emplace_back(token);
        token = strtok(nullptr, ",");
    }
    free(data);
    z_log("规则已动态更新，当前共加载 %zu 条路径", g_block_rules.size());
}

// --- Hook 安装逻辑 ---
static bool ensure_hooks_installed() {
    static bool installed = false;
    if (installed) return true;

    z_log("正在加载 ShadowHook 库...");
#ifdef __aarch64__
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif

    if (access(sh_path, F_OK) != 0) {
        z_log("错误: 找不到 libshadowhook.so (%s)", sh_path);
        return false;
    }

    void* handle = dlopen(sh_path, RTLD_NOW);
    if (!handle) { 
        z_log("dlopen 失败: %s", dlerror()); 
        return false; 
    }

    typedef int (*sh_init_t)(int, bool);
    auto sh_init = (sh_init_t)dlsym(handle, "shadowhook_init");
    if (!sh_init || sh_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
        z_log("ShadowHook 初始化失败");
        return false;
    }

    orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
    orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
    
    if (orig_openat && orig_mkdirat) {
        z_log("成功注入系统函数 (openat/mkdirat)");
        installed = true;
        return true;
    }
    z_log("符号 Hook 失败");
    return false;
}

// --- Socket 后台线程 (仅用于动态控制，不再阻塞注入) ---
static void connection_keeper_thread() {
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            sleep(5); 
            continue;
        }

        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d", g_process_name, getpid());
        write(fd, report, strlen(report));

        char buf[8192];
        while (true) {
            ssize_t len = read(fd, buf, sizeof(buf) - 1);
            if (len <= 0) break;
            buf[len] = 0;

            if (strncmp(buf, "SET_RULES:", 10) == 0) {
                update_rules(buf);
            } else if (strncmp(buf, "ENABLE_HOOK", 11) == 0) {
                // 虽然已经是自动 Hook，但这里可以作为手动重试
                ensure_hooks_installed();
                write(fd, "ALREADY_HOOKED", 14);
            } else if (strncmp(buf, "SKIP", 4) == 0) {
                close(fd); return;
            }
        }
        close(fd);
        sleep(2);
    }
}

// --- Companion 处理 (Root 侧转发) ---
static void companion_handler(int client_fd) {
    char buffer[1024] = {0};
    ssize_t n = read(client_fd, buffer, sizeof(buffer));
    if (n <= 0) { close(client_fd); return; }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    struct timeval tv = {2, 0};
    setsockopt(target_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "SKIP", 4); 
        close(client_fd); close(target_fd);
        return;
    }

    write(target_fd, buffer, n);
    std::thread([client_fd, target_fd]() {
        char b[8192];
        while (true) {
            ssize_t l = read(target_fd, b, sizeof(b));
            if (l <= 0) break;
            write(client_fd, b, l);
        }
        close(client_fd); close(target_fd);
    }).detach();
}

// --- Zygisk 模块主体 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        g_api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name) {
            if (strcmp(nice_name, "com.android.providers.media.module") == 0 ||
                strcmp(nice_name, "com.android.providers.media") == 0 ||
                strcmp(nice_name, "android.process.media") == 0 ||
                strcmp(nice_name, "com.google.android.providers.media") == 0) {
                
                g_is_media_process = true;
                strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
                
                // 1. 初始化硬编码规则
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                g_block_rules.emplace_back("/storage/emulated/0/Download/1DMP");
                
                z_log("检测到媒体进程，准备自动注入...");
            }
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // 2. 自动完成 Hook 注入 (不再等待后端指令)
        if (ensure_hooks_installed()) {
            z_log("媒体进程 Hook 成功完成");
        } else {
            z_log("警告: 媒体进程自动 Hook 失败");
        }

        // 3. 启动 Socket 线程以便接收后续动态规则
        std::thread(connection_keeper_thread).detach();
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)