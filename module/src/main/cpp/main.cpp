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
#define LOG_FILE_PATH "/data/Namespace-Proxy/log/zygisk.log"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static std::mutex g_log_mutex;
static zygisk::Api* g_api = nullptr; // 用于重连
static bool g_is_media_process = false;
static char g_process_name[256] = {0};

extern "C" const char* getprogname();

// --- 日志系统 ---
static void z_log(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", msg);

    FILE* fp = fopen(LOG_FILE_PATH, "a+");
    if (fp) {
        time_t now = time(nullptr);
        struct tm* t = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
        fprintf(fp, "[%s] [%d] %s\n", time_str, getpid(), msg);
        fclose(fp);
    }
}

// --- 辅助逻辑 ---
static bool is_media_blocked(const char* path) {
    if (!path || path[0] != '/') return false;
    if (strncmp(path, "/storage/", 9) != 0 && strncmp(path, "/sdcard", 7) != 0) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 函数 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_media_blocked(path)) {
        z_log("[BLOCK] openat: %s", path);
        errno = ENOENT; return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_media_blocked(path)) {
        z_log("[BLOCK] mkdirat: %s", path);
        errno = EACCES; return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 规则解析 ---
static void update_rules(const char* msg) {
    if (strncmp(msg, "SET_RULES:", 10) != 0) return;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    g_block_rules.clear();
    if (strlen(msg) <= 10) { z_log("Rules cleared"); return; }
    char* data = strdup(msg + 10);
    char* token = strtok(data, ",");
    while (token) {
        if (strlen(token) > 0) g_block_rules.emplace_back(token);
        token = strtok(nullptr, ",");
    }
    free(data);
    z_log("Rules updated: Loaded %zu paths", g_block_rules.size());
}

// --- Hook 初始化 ---
static bool ensure_hooks_installed() {
    static bool installed = false;
    if (installed) return true;

    z_log("Initializing ShadowHook...");
#ifdef __aarch64__
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
    const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif
    void* handle = dlopen(sh_path, RTLD_NOW);
    if (!handle) { z_log("dlopen failed: %s", dlerror()); return false; }

    typedef int (*sh_init_t)(int, bool);
    sh_init_t sh_init = (sh_init_t)dlsym(handle, "shadowhook_init");
    if (!sh_init || sh_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) return false;

    orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
    orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
    
    if (orig_openat && orig_mkdirat) {
        z_log("Hooks installed successfully");
        installed = true;
        return true;
    }
    return false;
}

// --- 核心：连接保持线程 ---
static void connection_keeper_thread() {
    z_log("Connection keeper thread started");

    while (true) {
        // 1. 尝试连接 Companion
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            // 连接失败，等待后重试
            sleep(3); 
            continue;
        }

        z_log("Connected to Companion (FD: %d), Handshaking...", fd);

        // 2. 发送身份报告 (Handshake)
        // Injector 重启后丢失了状态，必须重新发送 REPORT
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d", g_process_name, getpid());
        if (write(fd, report, strlen(report)) < 0) {
            z_log("Handshake failed");
            close(fd);
            sleep(2);
            continue;
        }

        // 3. 等待 Injector 响应
        char cmd[64] = {0};
        // 设置超时，避免 Injector 卡死导致我们一直等
        struct timeval tv = {2, 0}; 
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        ssize_t len = read(fd, cmd, sizeof(cmd) - 1);
        if (len <= 0) {
            z_log("Handshake response timeout or error");
            close(fd);
            sleep(2);
            continue;
        }
        cmd[len] = 0;

        // 4. 处理响应
        bool authorized = false;
        if (strncmp(cmd, "ENABLE_HOOK", 11) == 0) {
            authorized = true;
        } else if (strncmp(cmd, "SET_RULES:", 10) == 0) {
            update_rules(cmd);
            authorized = true;
        }

        if (authorized) {
            // 确保 Hook 已安装
            if (ensure_hooks_installed()) {
                write(fd, "SUCCESS: Hook Applied/Restored", 30);
                
                // 5. 进入监听循环 (阻塞读取规则更新)
                // 取消超时设置，以便长连接等待
                struct timeval no_tv = {0, 0};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &no_tv, sizeof(no_tv));

                char buf[8192];
                while (true) {
                    ssize_t n = read(fd, buf, sizeof(buf) - 1);
                    if (n <= 0) {
                        // Injector 断开或 crash
                        z_log("Connection lost (Injector died?), retrying...");
                        break; 
                    }
                    buf[n] = 0;
                    update_rules(buf);
                }
            } else {
                write(fd, "ERROR: Hook Install Failed", 26);
            }
        } else {
            z_log("Injector denied access: %s", cmd);
            // 如果被拒绝，可能不需要立即重试，或者等待更久
            close(fd);
            sleep(10);
            continue;
        }

        // 6. 清理并准备重连
        close(fd);
        sleep(1); // 避免 CPU 占用过高
    }
}

// --- Companion 处理 (Root) ---
static void companion_handler(int client_fd) {
    char buffer[1024] = {0};
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd); return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // 连接失败，直接关闭 Client FD，触发 Client 端的重连逻辑
        close(client_fd);
        close(target_fd);
        return;
    }

    write(target_fd, buffer, strlen(buffer));

    std::thread([client_fd, target_fd]() {
        char b[8192];
        while (true) {
            ssize_t l = read(target_fd, b, sizeof(b));
            if (l <= 0) break; // Injector 断开
            write(client_fd, b, l);
        }
        close(client_fd); // 关闭 Client FD，通知 App 重新连接
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
        g_api = api; // 保存 API 指针用于后续重连
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        // 简单的包名判断
        if (nice_name && (
            strcmp(nice_name, "com.android.providers.media.module") == 0 ||
            strcmp(nice_name, "com.android.providers.media") == 0 ||
            strcmp(nice_name, "android.process.media") == 0 ||
            strcmp(nice_name, "com.google.android.providers.media") == 0
        )) {
            g_is_media_process = true;
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }

        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // 启动守护线程，负责首次连接和断线重连
        std::thread(connection_keeper_thread).detach();
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)