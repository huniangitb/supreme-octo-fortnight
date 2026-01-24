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
        write(client_fd, "ERR_CONN", 8);
        close(client_fd);
        return;
    }

    write(target_fd, buffer, strlen(buffer));

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

class MediaBlockModule : public zygisk::ModuleBase {
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

        shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
        // 修正函数名：shadowhook_hook_sym_name
        orig_openat = shadowhook_hook_sym_name("libc.so", "openat", (void*)my_openat, nullptr);
        orig_mkdirat = shadowhook_hook_sym_name("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        char buffer[256];
        snprintf(buffer, sizeof(buffer), "INIT %s %d", process_name ? process_name : "unknown", getpid());
        write(g_companion_fd, buffer, strlen(buffer));

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);

        std::thread(rule_listener).detach();
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;
};

REGISTER_ZYGISK_MODULE(MediaBlockModule)
REGISTER_ZYGISK_COMPANION(companion_handler)