#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <fcntl.h>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <android/log.h>
#include <cerrno>
#include <poll.h>

#include "zygisk.hpp"
#include "dobby.h" 

#define LOG_TAG "NSProxy_Zygisk"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};
static std::atomic<bool> g_hooks_active(false);

static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

// --- 增强型日志函数 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    // 始终打印 PID 和 进程名
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[PID:%d][Process:%s] %s", getpid(), g_process_name, msg);
}

static bool is_path_blocked(const char* path) {
    if (!path || !g_hooks_active) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("拦截到路径访问 (openat): %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("拦截到路径访问 (mkdirat): %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

static bool install_hooks() {
    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat || !sym_mkdirat) {
        z_log("错误: 无法获取 libc 符号地址");
        return false;
    }

    int r1 = DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
    int r2 = DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);

    return (r1 == 0 && r2 == 0);
}

// --- 异步通讯线程 ---
static void async_setup_thread() {
    z_log("启动异步通讯线程...");
    
    if (install_hooks()) {
        g_hooks_active = true;
        z_log("Dobby Hooks 安装成功");
    } else {
        z_log("Dobby Hooks 安装失败！");
    }

    int retry_count = 0;
    while (true) {
        z_log("尝试连接 Companion (第 %d 次)...", ++retry_count);
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            z_log("错误: 无法连接 Companion (errno: %d, %s)", errno, strerror(errno));
            sleep(5);
            continue;
        }

        z_log("连接 Companion 成功，发送 PROXY_CONNECT...");
        if (write(fd, "PROXY_CONNECT", 13) <= 0) {
            z_log("发送 PROXY_CONNECT 失败");
            close(fd); sleep(5); continue;
        }

        z_log("等待 Companion 建立后端连接并响应 OK...");
        char ack[16] = {0};
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) <= 0) { // 3秒超时
            z_log("等待 Companion 响应超时");
            close(fd); sleep(5); continue;
        }

        if (read(fd, ack, sizeof(ack)) <= 0 || strcmp(ack, "OK") != 0) {
            z_log("Companion 握手失败: 收到 '%s'", ack);
            close(fd); sleep(5); continue;
        }

        z_log("与后端 injector 握手成功！开始上报状态...");
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        if (write(fd, report, strlen(report)) <= 0) {
            z_log("发送 REPORT 失败");
            close(fd); sleep(5); continue;
        }

        z_log("上报成功，进入规则接收模式...");
        char buf[8192];
        while (true) {
            ssize_t len = read(fd, buf, sizeof(buf) - 1);
            if (len <= 0) {
                z_log("通讯中断 (read 返回 %zd), 准备重连", len);
                break;
            }
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
                z_log("规则更新成功: 收到 %zu 条拦截规则", g_block_rules.size());
            }
        }
        close(fd);
        z_log("连接关闭，5秒后尝试重新同步...");
        sleep(5);
    }
}

// --- Companion 代理转发逻辑 ---
static void companion_handler(int client_fd) {
    char buf[64] = {0};
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) { close(client_fd); return; }

    if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(target_fd);
            close(client_fd);
            return;
        }

        // 先向 Client 回复 OK
        write(client_fd, "OK", 3);

        // 建立透明双向转发
        struct pollfd fds[2];
        fds[0].fd = client_fd; fds[0].events = POLLIN;
        fds[1].fd = target_fd; fds[1].events = POLLIN;
        char bridge_buf[4096];
        while (poll(fds, 2, -1) > 0) {
            for (int i = 0; i < 2; ++i) {
                if (fds[i].revents & POLLIN) {
                    int src = fds[i].fd;
                    int dst = (i == 0) ? target_fd : client_fd;
                    ssize_t n = read(src, bridge_buf, sizeof(bridge_buf));
                    if (n <= 0 || write(dst, bridge_buf, n) != n) goto bridge_end;
                }
                if (fds[i].revents & (POLLHUP | POLLERR)) goto bridge_end;
            }
        }
    bridge_end:
        close(target_fd);
        close(client_fd);
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
        z_log("已注入媒体进程，启动异步通讯...");
        std::thread(async_setup_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)