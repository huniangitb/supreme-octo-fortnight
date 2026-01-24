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

#include "zygisk.hpp"
#include "shadowhook.h"

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static int g_companion_fd = -1;

extern "C" const char* getprogname();

// 路径拦截判定
static bool is_media_blocked(const char* path) {
    if (!path) return false;
    if (strncmp(path, "/storage/", 9) != 0 && strncmp(path, "/sdcard", 7) != 0) return false;

    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// Hook 代理函数
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_media_blocked(path)) return -1;
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_media_blocked(path)) return -1;
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// 规则更新逻辑
static void update_rules(const char* msg) {
    if (strncmp(msg, "SET_RULES:", 10) != 0) return;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    g_block_rules.clear();
    char* data = strdup(msg + 10);
    char* token = strtok(data, ",");
    while (token) {
        g_block_rules.emplace_back(token);
        token = strtok(nullptr, ",");
    }
    free(data);
}

// 维持通信的规则监听线程
static void rule_listener() {
    char buf[1024];
    while (g_companion_fd >= 0) {
        ssize_t len = read(g_companion_fd, buf, sizeof(buf) - 1);
        if (len <= 0) break;
        buf[len] = '\0';
        update_rules(buf);
    }
}

// Companion 逻辑：处理指令转发
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

    // 同步获取指令 (ENABLE_HOOK 或 OK)
    char resp[64] = {0};
    ssize_t len = read(target_fd, resp, sizeof(resp) - 1);
    if (len > 0) write(client_fd, resp, (size_t)len);

    std::thread([client_fd, target_fd]() {
        char b[1024];
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
        if (args->uid < 1001) {
            this->companion_fd = -1;
            return;
        }
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;
        g_companion_fd = this->companion_fd;

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        // 1. 汇报基础信息
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "REPORT %s %d", process_name ? process_name : "unknown", getpid());
        write(g_companion_fd, buffer, strlen(buffer));

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);

        // 2. 接收指令判定
        char cmd[64] = {0};
        struct timeval tv = {0, 500000};
        setsockopt(g_companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        ssize_t len = read(g_companion_fd, cmd, sizeof(cmd) - 1);
        
        if (len > 0 && strncmp(cmd, "ENABLE_HOOK", 11) == 0) {
            // 3. 针对媒体应用：dlopen 确保依赖加载并执行 Hook
#ifdef __aarch64__
            const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
            const char* sh_path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif
            void* handle = dlopen(sh_path, RTLD_NOW);
            if (handle) {
                shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
                orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
                orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
                
                // 启动规则监听线程，不设置 DLCLOSE 选项
                std::thread(rule_listener).detach();
            }
        } else {
            // 4. 普通应用：直接卸载模块，清理环境
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
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