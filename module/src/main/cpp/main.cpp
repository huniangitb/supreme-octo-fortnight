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

// --- 这里必须与你的实际模块安装目录名一致 ---
#define MODULE_DIR_NAME "Namespace-Proxy"

// --- 全局状态 ---
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

// 接收 FD
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

// 发送 FD
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

// --- 路径判定逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    // 紧急硬编码保护
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;

    if (g_block_rules.empty()) return false;

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
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("[BLOCK] openat: %s", path);
        errno = ENOENT; return -1;
    }
    return ((openat_t)orig_openat)(fd, path, flags, mode);
}

typedef int (*mkdirat_t)(int, const char*, mode_t);
static void* orig_mkdirat = nullptr;
int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("[BLOCK] mkdirat: %s", path);
        errno = EACCES; return -1;
    }
    return ((mkdirat_t)orig_mkdirat)(fd, path, mode);
}

// --- 核心：从 FD 加载 ShadowHook (带重试) ---
static bool install_hooks_via_fd() {
    static bool hooks_installed = false;
    if (hooks_installed) return true;

    int client_fd = -1;
    int retries = 5; // 重试 5 次
    
    while (retries > 0) {
        client_fd = g_api->connectCompanion();
        if (client_fd >= 0) break;
        
        // 打印具体错误码，方便调试
        z_log("Companion 连接失败 (剩余重试 %d): %s (%d)", retries - 1, strerror(errno), errno);
        usleep(200000); // 等待 200ms
        retries--;
    }

    if (client_fd < 0) {
        z_log("严重错误: 无法连接 Companion，放弃 Hook。");
        return false;
    }

    if (write(client_fd, "GET_SH_FD", 10) != 10) {
        z_log("错误: 发送请求失败");
        close(client_fd);
        return false;
    }

    int sh_fd = recv_fd(client_fd);
    close(client_fd);

    if (sh_fd < 0) {
        z_log("错误: 无法获取 libshadowhook.so FD (请检查模块是否正确安装)");
        return false;
    }

    android_dlextinfo extinfo;
    memset(&extinfo, 0, sizeof(extinfo));
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = sh_fd;

    // 尝试加载
    void* handle = android_dlopen_ext("libshadowhook.so", RTLD_NOW, &extinfo);
    close(sh_fd);

    if (!handle) {
        z_log("错误: dlopen 失败: %s", dlerror());
        return false;
    }

    auto sh_init = (int (*)(int, bool))dlsym(handle, "shadowhook_init");
    auto sh_hook = (void* (*)(const char*, const char*, void*, void**))dlsym(handle, "shadowhook_hook_sym_name");

    if (!sh_init || !sh_hook) {
        z_log("错误: 符号解析失败");
        return false;
    }

    if (sh_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
        z_log("错误: ShadowHook 初始化失败");
        return false;
    }

    orig_openat = sh_hook("libc.so", "openat", (void*)my_openat, nullptr);
    orig_mkdirat = sh_hook("libc.so", "mkdirat", (void*)my_mkdirat, nullptr);

    if (orig_openat && orig_mkdirat) {
        z_log("HOOK 成功激活");
        hooks_installed = true;
        g_hooks_active = true;
        return true;
    }
    return false;
}

// --- 通信保持线程 ---
static void connection_keeper_thread() {
    sleep(2); // 等待 Injector 启动
    
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            sleep(5); continue; 
        }
        
        // 1. 请求代理连接
        if (write(fd, "PROXY_CONNECT", 14) != 14) {
            close(fd); sleep(1); continue;
        }
        
        // 2. 发送上报 (协议匹配 injector.c)
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        
        if (write(fd, report, strlen(report)) < 0) {
            close(fd); sleep(2); continue;
        }

        // 3. 接收规则
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
                int count = 0;
                while (token) {
                    while(*token == ' ') token++;
                    if (strlen(token) > 0) {
                        g_block_rules.emplace_back(token);
                        count++;
                    }
                    token = strtok(nullptr, ",");
                }
                z_log("规则已更新: %d 条", count);
            }
        }
        close(fd);
        sleep(5); 
    }
}

// --- Socket 桥接 ---
static void socket_bridge(int fd1, int fd2) {
    char buf[4096];
    while (true) {
        ssize_t len = read(fd1, buf, sizeof(buf));
        if (len <= 0) break;
        if (write(fd2, buf, len) != len) break;
    }
    shutdown(fd1, SHUT_RDWR);
    shutdown(fd2, SHUT_RDWR);
}

// --- Companion 处理 (Root 进程) ---
static void companion_handler(int client_fd) {
    char buf[64];
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = 0;

    if (strcmp(buf, "GET_SH_FD") == 0) {
        // 动态构建路径，防止硬编码错误
        char path[512];
#ifdef __aarch64__
        snprintf(path, sizeof(path), "/data/adb/modules/%s/lib/arm64-v8a/libshadowhook.so", MODULE_DIR_NAME);
#else
        snprintf(path, sizeof(path), "/data/adb/modules/%s/lib/armeabi-v7a/libshadowhook.so", MODULE_DIR_NAME);
#endif
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            send_fd(client_fd, fd);
            close(fd);
        } else {
            // 在 Root 进程打印错误，方便 logcat 排查
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Companion 找不到 lib: %s (errno=%d)", path, errno);
            write(client_fd, "ERR", 3);
        }
        close(client_fd);
    } 
    else if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(target_fd); 
            close(client_fd); 
            return;
        }

        std::thread t1([target_fd, client_fd]() { socket_bridge(target_fd, client_fd); });
        socket_bridge(client_fd, target_fd); // 主线程做上行
        if (t1.joinable()) t1.join();

        close(client_fd); 
        close(target_fd);
    } else {
        close(client_fd);
    }
}

class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        g_api = api; 
        this->env = env; 
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name && (
            strstr(nice_name, "android.providers.media") || 
            strstr(nice_name, "android.process.media") ||
            strcmp(nice_name, "com.android.providers.media.module") == 0
        )) {
            g_is_media_process = true;
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }
        
        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) { 
            g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); 
            return; 
        }
        
        // 核心修复：现在这里包含了重试逻辑
        if (install_hooks_via_fd()) {
            std::thread(connection_keeper_thread).detach();
        }
    }

private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)