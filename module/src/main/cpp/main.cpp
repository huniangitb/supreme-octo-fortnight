#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h> // 必须：用于控制信息
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
#include <android/dlext.h>

#include "zygisk.hpp"
#include "shadowhook.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局状态 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};

static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

static int send_fd(int socket, int fd) {
    struct msghdr msg = {0};
    char buf[1] = {0};
    struct iovec io = {.iov_base = buf, .iov_len = 1};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    *((int *)CMSG_DATA(cmptr)) = fd;

    return sendmsg(socket, &msg, 0);
}

static int recv_fd(int socket) {
    struct msghdr msg = {0};
    char buf[1];
    struct iovec io = {.iov_base = buf, .iov_len = 1};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    if (recvmsg(socket, &msg, 0) <= 0) return -1;

    struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
    if (cmptr && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level == SOL_SOCKET && cmptr->cmsg_type == SCM_RIGHTS) {
            return *((int *)CMSG_DATA(cmptr));
        }
    }
    return -1;
}

// --- 路径判定逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;

    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 回调 ---
typedef int (*openat_t)(int, const char*, int, mode_t);
static void* orig_openat = nullptr;
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("[拦截] openat: %s", path);
        errno = ENOENT; return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("[拦截] mkdirat: %s", path);
        errno = EACCES; return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 核心逻辑：从 FD 加载 ShadowHook ---
static bool install_hooks_via_fd() {
    static bool hooks_installed = false;
    if (hooks_installed) return true;

    int client_fd = g_api->connectCompanion();
    if (client_fd < 0) return false;

    write(client_fd, "GET_SH_FD", 10);
    int sh_fd = recv_fd(client_fd); // 使用我们的静态函数
    close(client_fd);

    if (sh_fd < 0) {
        z_log("错误: 无法从 Companion 获取 FD");
        return false;
    }

    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = sh_fd;

    // 从 FD 加载，避开路径权限检查
    void* handle = android_dlopen_ext("libshadowhook.so", RTLD_NOW, &extinfo);
    close(sh_fd);

    if (!handle) {
        z_log("错误: android_dlopen_ext 失败: %s", dlerror());
        return false;
    }

    auto sh_init = (int (*)(int, bool))dlsym(handle, "shadowhook_init");
    auto sh_hook = (void* (*)(const char*, const char*, void*, void**))dlsym(handle, "shadowhook_hook_sym_name");

    if (!sh_init || !sh_hook || sh_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
        z_log("错误: ShadowHook 初始化或符号查找失败");
        return false;
    }

    orig_openat = sh_hook("libc.so", "openat", (void*)my_openat, nullptr);
    orig_mkdirat = sh_hook("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);

    if (orig_openat && orig_mkdirat) {
        z_log("成功: 已通过 FD 绕过 SELinux 完成 Hook");
        hooks_installed = true;
        return true;
    }
    return false;
}

// --- 通信保持线程 ---
static void connection_keeper_thread() {
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) { sleep(5); continue; }
        
        write(fd, "PROXY_CONNECT", 14);
        
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:OK", g_process_name, getpid());
        write(fd, report, strlen(report));

        char buf[4096];
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
                z_log("动态规则已更新");
            }
        }
        close(fd);
        sleep(2);
    }
}

// --- Companion 处理 ---
static void companion_handler(int client_fd) {
    char buf[64];
    ssize_t n = read(client_fd, buf, sizeof(buf));
    if (n <= 0) { close(client_fd); return; }

    if (strcmp(buf, "GET_SH_FD") == 0) {
#ifdef __aarch64__
        const char* path = "/data/adb/modules/Namespace-Proxy/lib/arm64-v8a/libshadowhook.so";
#else
        const char* path = "/data/adb/modules/Namespace-Proxy/lib/armeabi-v7a/libshadowhook.so";
#endif
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            send_fd(client_fd, fd); // 使用我们的静态函数
            close(fd);
        } else {
            // 发送一个无效标志
            struct msghdr msg = {0};
            char dummy[1] = {0};
            struct iovec io = {.iov_base = dummy, .iov_len = 1};
            msg.msg_iov = &io;
            msg.msg_iovlen = 1;
            sendmsg(client_fd, &msg, 0);
        }
        close(client_fd);
    } 
    else if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(target_fd); close(client_fd); return;
        }
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
        install_hooks_via_fd();
        std::thread(connection_keeper_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)