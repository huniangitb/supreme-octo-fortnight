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

#include "zygisk.hpp"
#include "shadowhook.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局变量 ---
static std.vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};

// --- 增强型日志系统 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

// --- 路径判定逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) {
        return true;
    }
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 回调函数 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("[拦截] openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("[拦截] mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- ShadowHook 加载与安装 ---
static bool install_hooks() {
    static bool hooks_installed = false;
    if (hooks_installed) return true;

    z_log("开始加载 ShadowHook 并注入拦截逻辑...");

#ifdef __aarch64__
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif

    void* handle = dlopen(sh_path, RTLD_NOW);
    if (!handle) {
        z_log("错误: 无法加载 libshadowhook.so: %s", dlerror());
        return false;
    }

    // dlsym shadowhook_init
    auto sh_init = (int (*)(int, bool))dlsym(handle, "shadowhook_init");
    if (!sh_init || sh_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
        z_log("错误: shadowhook_init 失败");
        dlclose(handle);
        return false;
    }

    // 【关键修复】
    // dlsym shadowhook_hook_sym_name，以避免链接器错误
    typedef void* (*sh_hook_sym_name_t)(const char*, const char*, void*, void**);
    auto sh_hook_sym_name = (sh_hook_sym_name_t)dlsym(handle, "shadowhook_hook_sym_name");
    if (!sh_hook_sym_name) {
        z_log("错误: dlsym shadowhook_hook_sym_name 失败");
        dlclose(handle);
        return false;
    }

    // 通过函数指针调用 Hook
    orig_openat = sh_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
    orig_mkdirat = sh_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);

    if (orig_openat && orig_mkdirat) {
        z_log("成功: 系统 Hook 已自动安装 (openat/mkdirat)");
        hooks_installed = true;
        // 注意：这里不应该 dlclose(handle)，否则 Hook 会失效
        return true;
    } else {
        z_log("错误: shadowhook_hook_sym_name 调用失败");
        // 如果 Hook 失败，可以关闭句柄
        dlclose(handle);
        return false;
    }
}

// --- 通信线程 (用于实时上报与动态规则) ---
static void connection_keeper_thread() {
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            sleep(5);
            continue;
        }
        char report[512];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        write(fd, report, strlen(report));
        char buf[8192];
        while (true) {
            ssize_t len = read(fd, buf, sizeof(buf) - 1);
            if (len <= 0) break;
            buf[len] = 0;
            if (strncmp(buf, "SET_RULES:", 10) == 0) {
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                g_block_rules.clear();
                char* data = strdup(buf + 10);
                char* token = strtok(data, ",");
                while (token) {
                    if (strlen(token) > 0) g_block_rules.emplace_back(token);
                    token = strtok(nullptr, ",");
                }
                free(data);
                z_log("动态规则已同步，当前总规则数: %zu", g_block_rules.size());
            } else if (strncmp(buf, "SKIP", 4) == 0) {
                close(fd);
                return;
            }
        }
        close(fd);
        sleep(2);
    }
}

// --- Companion (Root 侧转发逻辑) ---
static void companion_handler(int client_fd) {
    char buffer[1024];
    ssize_t n = read(client_fd, buffer, sizeof(buffer));
    if (n <= 0) { close(client_fd); return; }
    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "SKIP", 4);
        close(client_fd); close(target_fd);
        return;
    }
    write(target_fd, buffer, n);
    std::thread([client_fd, target_fd]() {
        char b[4096];
        while (true) {
            ssize_t l = read(target_fd, b, sizeof(b));
            if (l <= 0) break;
            write(client_fd, b, l);
        }
        close(client_fd); close(target_fd);
    }).detach();
}

// --- Zygisk Module ---
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
            if (strstr(nice_name, "android.providers.media") ||
                strstr(nice_name, "android.process.media") ||
                strstr(nice_name, "com.google.android.providers.media")) {
                g_is_media_process = true;
                strncpy(g_process_name, nice_name, sizeof(g_process_name) - 1);
            }
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        install_hooks();
        std::thread(connection_keeper_thread).detach();
        z_log("媒体注入流程初始化完毕");
    }
private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)