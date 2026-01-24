#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
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

#include "zygisk.hpp"
#include "shadowhook.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"
#define MODULE_DIR_NAME "Namespace-Proxy"

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

// --- 基础工具函数 ---
static int recv_fd(int socket) {
    struct msghdr msg = {0};
    char buf[1];
    struct iovec io = {.iov_base = buf, .iov_len = 1};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    union { struct cmsghdr cm; char control[CMSG_SPACE(sizeof(int))]; } control_un;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    if (recvmsg(socket, &msg, 0) <= 0) return -1;
    struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
    if (cmptr && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level == SOL_SOCKET && cmptr->cmsg_type == SCM_RIGHTS) return *((int *)CMSG_DATA(cmptr));
    }
    return -1;
}

static int send_fd(int socket, int fd) {
    struct msghdr msg = {0};
    char buf[1] = {0};
    struct iovec io = {.iov_base = buf, .iov_len = 1};
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    union { struct cmsghdr cm; char control[CMSG_SPACE(sizeof(int))]; } control_un;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    *((int *)CMSG_DATA(cmptr)) = fd;
    return sendmsg(socket, &msg, 0);
}

// --- 路径判定 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 实现 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("[拦截] openat: %s", path);
        errno = ENOENT; return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("[拦截] mkdirat: %s", path);
        errno = EACCES; return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 异步加载与通讯 ---
static void async_setup_thread() {
    // 1. 延迟启动，避开进程初始化最繁忙的时刻
    sleep(1);

    int client_fd = -1;
    int retries = 10;
    while (retries-- > 0) {
        client_fd = g_api->connectCompanion();
        if (client_fd >= 0) break;
        usleep(300000);
    }

    if (client_fd < 0) {
        z_log("无法连接 Companion: %s", strerror(errno));
        return;
    }

    // 2. 获取 ShadowHook FD 并加载
    write(client_fd, "GET_SH_FD", 10);
    int sh_fd = recv_fd(client_fd);
    close(client_fd);

    if (sh_fd >= 0) {
        android_dlextinfo extinfo;
        memset(&extinfo, 0, sizeof(extinfo));
        extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        extinfo.library_fd = sh_fd;
        void* handle = android_dlopen_ext("libshadowhook.so", RTLD_NOW, &extinfo);
        close(sh_fd);

        if (handle) {
            auto sh_init = (int (*)(int, bool))dlsym(handle, "shadowhook_init");
            auto sh_hook = (void* (*)(const char*, const char*, void*, void**))dlsym(handle, "shadowhook_hook_sym_name");
            if (sh_init && sh_hook && sh_init(SHADOWHOOK_MODE_UNIQUE, false) == 0) {
                orig_openat = sh_hook("libc.so", "openat", (void*)my_openat, nullptr);
                orig_mkdirat = sh_hook("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);
                if (orig_openat) {
                    z_log("ShadowHook 已就绪");
                    g_hooks_active = true;
                }
            }
        } else {
            z_log("dlopen 失败: %s", dlerror());
        }
    }

    // 3. 持续保持规则更新通讯
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) { sleep(5); continue; }

        write(fd, "PROXY_CONNECT", 14);
        char report[256];
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
                char* data = buf + 10;
                char* token = strtok(data, ",");
                while (token) {
                    if (*token) g_block_rules.emplace_back(token);
                    token = strtok(nullptr, ",");
                }
                z_log("规则更新成功");
            }
        }
        close(fd);
        sleep(10);
    }
}

// --- Companion 逻辑 (Root 进程) ---
static void socket_bridge(int fd1, int fd2) {
    char buf[4096];
    ssize_t len;
    while ((len = read(fd1, buf, sizeof(buf))) > 0) {
        if (write(fd2, buf, len) != len) break;
    }
    close(fd1); close(fd2);
}

static void companion_handler(int client_fd) {
    char buf[64] = {0};
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) { close(client_fd); return; }

    if (strcmp(buf, "GET_SH_FD") == 0) {
        char path[512];
#ifdef __aarch64__
        snprintf(path, sizeof(path), "/data/adb/modules/%s/lib/arm64-v8a/libshadowhook.so", MODULE_DIR_NAME);
#else
        snprintf(path, sizeof(path), "/data/adb/modules/%s/lib/armeabi-v7a/libshadowhook.so", MODULE_DIR_NAME);
#endif
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { send_fd(client_fd, fd); close(fd); }
        close(client_fd);
    } 
    else if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(target_fd); close(client_fd); return;
        }
        // [关键修复] 绝不 join，detach 线程后立即让 handler 返回
        std::thread([target_fd, client_fd]() { socket_bridge(target_fd, client_fd); }).detach();
        std::thread([client_fd, target_fd]() { socket_bridge(client_fd, target_fd); }).detach();
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
            g_is_media_process = true;
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }
        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) { g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); return; }
        // 整个流程完全异步，不影响系统进程启动
        std::thread(async_setup_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)