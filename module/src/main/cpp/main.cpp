#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
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
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static int g_companion_fd = -1;

extern "C" const char* getprogname();

// --- 路径拦截判定 ---
static bool is_media_blocked(const char* path) {
    if (!path) return false;
    // 快速过滤：仅处理存储相关的绝对路径
    if (path[0] != '/') return false;
    if (strncmp(path, "/storage/", 9) != 0 && strncmp(path, "/sdcard", 7) != 0) return false;

    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 代理函数 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_media_blocked(path)) {
        LOGD("[INTERCEPT] Blocked openat: %s", path);
        errno = ENOENT; 
        return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_media_blocked(path)) {
        LOGD("[INTERCEPT] Blocked mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 规则监听逻辑 ---
static void update_rules(const char* msg) {
    if (strncmp(msg, "SET_RULES:", 10) != 0) return;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    g_block_rules.clear();
    if (strlen(msg) <= 10) return;

    char* data = strdup(msg + 10);
    char* token = strtok(data, ",");
    while (token) {
        if (strlen(token) > 0) g_block_rules.emplace_back(token);
        token = strtok(nullptr, ",");
    }
    free(data);
    LOGD("Rules updated: %zu prefixes loaded", g_block_rules.size());
}

static void rule_listener() {
    char buf[8192];
    while (g_companion_fd >= 0) {
        ssize_t len = read(g_companion_fd, buf, sizeof(buf) - 1);
        if (len <= 0) break;
        buf[len] = '\0';
        update_rules(buf);
    }
    LOGD("Rule listener thread terminated");
}

// --- Companion 逻辑 ---
static void companion_handler(int client_fd) {
    char buffer[1024] = {0};
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd);
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        write(client_fd, "SKIP", 4);
        close(client_fd);
        return;
    }

    write(target_fd, buffer, strlen(buffer));

    // 转发指令并保持双向通信
    std::thread([client_fd, target_fd]() {
        char b[8192];
        while (true) {
            ssize_t l = read(target_fd, b, sizeof(b));
            if (l <= 0) break;
            write(client_fd, b, l);
        }
        close(client_fd);
        close(target_fd);
    }).detach();
}

class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // UID 过滤在 Injector 端包名判定后通过 SKIP 指令执行，此处全量连接
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;
        g_companion_fd = this->companion_fd;

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        // 1. 上报
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d", process_name ? process_name : "unknown", getpid());
        write(g_companion_fd, report, strlen(report));

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);

        // 2. 等待指令
        char cmd[64] = {0};
        struct timeval tv = {1, 0}; // 1秒超时
        setsockopt(g_companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        ssize_t len = read(g_companion_fd, cmd, sizeof(cmd) - 1);
        
        if (len > 0 && strncmp(cmd, "ENABLE_HOOK", 11) == 0) {
            LOGD("Media Provider Hooking started...");
            
            // 3. 加载诊断
#ifdef __aarch64__
            const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
            const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif

            void* handle = dlopen(sh_path, RTLD_NOW);
            if (!handle) {
                char err_msg[512];
                snprintf(err_msg, sizeof(err_msg), "ERROR: dlopen failed: %s", dlerror());
                LOGE("%s", err_msg);
                write(g_companion_fd, err_msg, strlen(err_msg));
                goto cleanup;
            }

            if (shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
                const char* err = "ERROR: shadowhook_init failed";
                LOGE("%s", err);
                write(g_companion_fd, err, strlen(err));
                goto cleanup;
            }

            orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
            orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);

            if (!orig_openat || !orig_mkdirat) {
                const char* err = "ERROR: Failed to hook openat/mkdirat";
                LOGE("%s", err);
                write(g_companion_fd, err, strlen(err));
                goto cleanup;
            }

            // 全部成功
            LOGD("ShadowHook initialized and symbols hooked successfully.");
            write(g_companion_fd, "SUCCESS: Hook Applied", 21);
            
            // 启动异步规则监听
            std::thread(rule_listener).detach();
            return; // 保持模块加载
        }

cleanup:
        LOGD("Cleaning up zygisk module for non-target process or failure.");
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        if (g_companion_fd >= 0) {
            close(g_companion_fd);
            g_companion_fd = -1;
        }
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)