#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/uio.h>
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
#include "dobby.h" // 确保你的编译环境包含了 Dobby 库

#define LOG_TAG "NSProxy_Zygisk"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局变量 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static std::string g_process_name = "unknown";
static std::atomic<bool> g_hooks_installed(false);

// --- 原始函数指针 ---
static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

// --- 诊断日志 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[PID:%d][%s] %s", getpid(), g_process_name.c_str(), msg);
}

// --- 核心拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path || !g_hooks_installed) return false;
    
    // 1. 静态规则 (用于初步测试)
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;

    // 2. 动态规则 (从后端获取)
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Proxy 函数 ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("拦截访问 (openat): %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_path_blocked(path)) {
        z_log("拦截创建 (mkdirat): %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Hook 安装 ---
static void install_hooks_once() {
    if (g_hooks_installed) return;

    z_log("开始解析 libc 符号...");
    // 尝试多种方式解析符号，增加兼容性
    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat) sym_openat = DobbySymbolResolver(nullptr, "openat");
    if (!sym_mkdirat) sym_mkdirat = DobbySymbolResolver(nullptr, "mkdirat");

    if (sym_openat && sym_mkdirat) {
        DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
        DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
        g_hooks_installed = true;
        z_log("Dobby Hooks 安装成功");
    } else {
        z_log("错误: 无法解析核心符号 (openat:%p, mkdirat:%p)", sym_openat, sym_mkdirat);
    }
}

// --- 通讯线程 ---
static void async_communication_worker() {
    z_log("异步通讯线程已启动");
    install_hooks_once();

    int fail_count = 0;
    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            if (++fail_count % 10 == 0) z_log("连接 Companion 持续失败 (errno: %d)", errno);
            sleep(5);
            continue;
        }

        // 1. 发送连接握手
        if (write(fd, "PROXY_CONNECT", 13) <= 0) {
            close(fd); sleep(5); continue;
        }

        // 2. 等待 ACK
        char ack[16] = {0};
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) > 0) {
            if (read(fd, ack, sizeof(ack) - 1) > 0 && strcmp(ack, "OK") == 0) {
                z_log("已通过 Companion 连接到后端 injector");
                
                // 3. 上报进程信息
                char report[256];
                snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name.c_str(), getpid());
                write(fd, report, strlen(report));

                // 4. 循环读取规则
                char buf[8192];
                while (true) {
                    ssize_t n = read(fd, buf, sizeof(buf) - 1);
                    if (n <= 0) break;
                    buf[n] = 0;

                    if (strncmp(buf, "SET_RULES:", 10) == 0) {
                        std::lock_guard<std::mutex> lock(g_rule_mutex);
                        g_block_rules.clear();
                        char* data = buf + 10;
                        char* token = strtok(data, ",");
                        while (token) {
                            if (*token) g_block_rules.emplace_back(token);
                            token = strtok(nullptr, ",");
                        }
                        z_log("动态规则更新成功, 数量: %zu", g_block_rules.size());
                    }
                }
            }
        }
        
        close(fd);
        z_log("连接已断开，5秒后重连...");
        sleep(5);
    }
}

// --- Companion 逻辑 (运行在 root 进程) ---
static void companion_handler(int client_fd) {
    char buf[64] = {0};
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) {
        close(client_fd);
        return;
    }

    if (strcmp(buf, "PROXY_CONNECT") == 0) {
        // 创建连接到后端 injector 的真正的 Unix Socket
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            // 如果后端没开，直接关掉
            close(target_fd);
            close(client_fd);
            return;
        }

        // 告知 Client 端，通道已建立
        write(client_fd, "OK", 3);

        // 透明转发双向数据
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
                    if (n <= 0) goto bridge_exit;
                    if (write(dst, bridge_buf, n) != n) goto bridge_exit;
                }
                if (fds[i].revents & (POLLHUP | POLLERR)) goto bridge_exit;
            }
        }
    bridge_exit:
        close(target_fd);
        close(client_fd);
    } else {
        close(client_fd);
    }
}

// --- Zygisk 模块主体 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        g_api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args->nice_name) return;
        
        const char* nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!nice_name) return;

        // 检查是否是目标媒体进程
        if (strstr(nice_name, "android.providers.media") || 
            strstr(nice_name, "android.process.media") ||
            strstr(nice_name, "com.android.providers.media.module")) {
            
            g_is_media_process = true;
            g_process_name = nice_name;
        }

        env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (g_is_media_process) {
            z_log("Zygisk 注入确认，启动通讯线程...");
            // 必须在 postAppSpecialize 之后启动线程，否则可能导致 fork 失败
            std::thread(async_communication_worker).detach();
        } else {
            // 如果不是目标进程，立即卸载模块以节省资源
            g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

private:
    JNIEnv *env;
};

// 注册模块
REGISTER_ZYGISK_MODULE(MediaTargetModule)
// 注册 Companion
REGISTER_ZYGISK_COMPANION(companion_handler)