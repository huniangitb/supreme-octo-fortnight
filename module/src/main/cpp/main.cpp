#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
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

// 路径过滤：仅针对媒体路径
static bool is_media_blocked(const char* path) {
    if (!path) return false;
    if (strncmp(path, "/storage/", 9) != 0 && strncmp(path, "/sdcard", 7) != 0) return false;

    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

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

static void rule_listener() {
    char buf[1024];
    while (g_companion_fd >= 0) {
        ssize_t len = read(g_companion_fd, buf, sizeof(buf) - 1);
        if (len <= 0) break;
        buf[len] = '\0';
        update_rules(buf);
    }
}

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
        write(client_fd, "SKIP", 4); // 连接后端失败默认放行
        close(client_fd);
        return;
    }

    write(target_fd, buffer, strlen(buffer));

    // 同步等待后端返回：ENABLE_HOOK 或 OK
    char resp[64] = {0};
    ssize_t len = read(target_fd, resp, sizeof(resp) - 1);
    if (len > 0) write(client_fd, resp, (size_t)len);

    // 建立双向转发维持规则更新通道
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

class TargetedBlockerModule : public zygisk::ModuleBase {
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

        // 汇报进程信息
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "REPORT %s %d", process_name ? process_name : "unknown", getpid());
        write(g_companion_fd, buffer, strlen(buffer));

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);

        // 等待命令决定是否开启 Hook
        char cmd[64] = {0};
        struct timeval tv = {0, 500000}; // 0.5秒等待
        setsockopt(g_companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        ssize_t len = read(g_companion_fd, cmd, sizeof(cmd) - 1);
        
        if (len > 0 && strncmp(cmd, "ENABLE_HOOK", 11) == 0) {
            // 需要 Hook，则不设置 DLCLOSE 选项，保持动态库驻留
            shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
            orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
            orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
            
            // 开启监听线程实时更新拦截规则
            std::thread(rule_listener).detach();
        } else {
            // 普通应用，卸载模块代码以节省资源并消除特征
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

REGISTER_ZYGISK_MODULE(TargetedBlockerModule)
REGISTER_ZYGISK_COMPANION(companion_handler)