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

// 路径拦截判定
static bool is_media_blocked(const char* path) {
    if (!path) return false;
    // 性能优化：仅检查 /storage 和 /sdcard
    if (strncmp(path, "/storage/", 9) != 0 && strncmp(path, "/sdcard", 7) != 0) return false;

    std::lock_guard<std::mutex> lock(g_rule_mutex);
    if (g_block_rules.empty()) return false;

    for (const auto& prefix : g_block_rules) {
        // 使用 strstr 进行子串匹配，确保原路径及其子路径都被拦截
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// Hook 代理函数
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_media_blocked(path)) {
        errno = ENOENT; // 返回文件不存在
        return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_media_blocked(path)) {
        errno = EACCES;
        return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// 规则更新逻辑
static void update_rules(const char* msg) {
    if (strncmp(msg, "SET_RULES:", 10) != 0) return;
    
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    g_block_rules.clear();
    
    // 如果消息只有 "SET_RULES:" 没有后续内容，说明清空规则
    if (strlen(msg) <= 10) return;

    char* data = strdup(msg + 10);
    if (!data) return;

    char* token = strtok(data, ",");
    while (token) {
        if (strlen(token) > 0) {
            g_block_rules.emplace_back(token);
            LOGD("Add Block Rule: %s", token);
        }
        token = strtok(nullptr, ",");
    }
    free(data);
}

// 维持通信的规则监听线程
static void rule_listener() {
    char buf[8192]; // 足够大以容纳规则
    while (g_companion_fd >= 0) {
        ssize_t len = read(g_companion_fd, buf, sizeof(buf) - 1);
        if (len <= 0) break;
        buf[len] = '\0';
        update_rules(buf);
    }
    LOGD("Rule listener exited");
}

// Companion 逻辑：处理指令转发
static void companion_handler(int client_fd) {
    char buffer[1024] = {0};
    // 读取 App 发送的 REPORT 指令
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd);
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        write(client_fd, "SKIP", 4); // 连接失败，默认跳过
        close(client_fd);
        return;
    }

    // 转发 REPORT 给 Injector
    write(target_fd, buffer, strlen(buffer));

    // 同步获取 Injector 的第一条指令 (ENABLE_HOOK 或 SKIP)
    char resp[64] = {0};
    ssize_t len = read(target_fd, resp, sizeof(resp) - 1);
    if (len > 0) {
        write(client_fd, resp, (size_t)len);
    }

    // 如果 Injector 决定启用 Hook，它后续可能会发送 SET_RULES
    // 开启线程进行全双工转发 (主要是 Target -> Client)
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
        // UID 过滤，普通应用直接跳过
        // 注意：Media Provider 也是 system uid 级别，不能简单用 uid > 10000 过滤
        // 这里不做严格过滤，交给 companion 连接 Injector 后由 Injector 判断包名
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;
        g_companion_fd = this->companion_fd;

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        // 1. 汇报基础信息 REPORT <pkg> <pid>
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "REPORT %s %d", process_name ? process_name : "unknown", getpid());
        write(g_companion_fd, buffer, strlen(buffer));

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);

        // 2. 接收指令判定
        char cmd[64] = {0};
        struct timeval tv = {0, 500000}; // 500ms 超时
        setsockopt(g_companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        ssize_t len = read(g_companion_fd, cmd, sizeof(cmd) - 1);
        
        if (len > 0 && strncmp(cmd, "ENABLE_HOOK", 11) == 0) {
            LOGD("Hook enabled for media provider");
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
                
                if (shadowhook_get_errno() == 0) {
                    LOGD("ShadowHook installed successfully");
                } else {
                    LOGE("ShadowHook failed: %d", shadowhook_get_errno());
                }

                // 启动规则监听线程，接收后续的 SET_RULES
                std::thread(rule_listener).detach();
            } else {
                LOGE("Failed to load libshadowhook.so: %s", dlerror());
            }
        } else {
            // 4. 普通应用或连接失败：直接卸载模块，清理环境
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