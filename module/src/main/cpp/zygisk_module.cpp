#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

// --- 全局变量 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static std::atomic<bool> g_hooks_active(false);
static char g_process_name[256] = {"unknown"};

// --- 原始函数指针 ---
static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

// --- 路径拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path || !g_hooks_active) return false;
    
    // 基础硬编码逻辑
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    
    // 动态规则匹配
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- Hook 代理函数 ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_path_blocked(path)) {
        LOGI("已拦截 openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_path_blocked(path)) {
        LOGI("已拦截 mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Dobby 安装逻辑 ---
static bool install_hooks() {
    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat || !sym_mkdirat) {
        sym_openat = DobbySymbolResolver(nullptr, "openat");
        sym_mkdirat = DobbySymbolResolver(nullptr, "mkdirat");
    }

    if (!sym_openat || !sym_mkdirat) return false;

    DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
    DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
    
    return true;
}

// --- Companion 处理逻辑 (运行在 Root 权限) ---
static void companion_handler(int client_fd) {
    char buffer[8192] = {0}; // 调大缓冲区以接收长规则
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    // 1. 检查后端锁文件，防止无效连接
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        write(client_fd, "ERR_NO_BACKEND", 14);
        close(client_fd);
        return;
    }

    // 2. 连接后端实际的 Socket
    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        write(client_fd, "ERR_SOCKET_FAIL", 15);
        close(client_fd);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        write(client_fd, "ERR_CONN_BACKEND", 16);
        close(client_fd);
        return;
    }

    // 3. 转发 App 消息给后端 (例如 "REPORT pkg pid STATUS:HOOKED")
    write(target_fd, buffer, strlen(buffer));
    
    // 4. 读取后端返回的内容 (可能是 "OK" 或 "SET_RULES:...")
    char backend_resp[8192] = {0};
    struct timeval tv = {2, 0}; // 2秒超时
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t resp_len = read(target_fd, backend_resp, sizeof(backend_resp) - 1);
    if (resp_len > 0) {
        // 5. 将结果回传给 App 进程
        write(client_fd, backend_resp, resp_len);
    } else {
        write(client_fd, "OK_TIMEOUT", 10);
    }

    close(target_fd);
    close(client_fd);
}

// --- Zygisk 模块主体 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 过滤系统核心进程
        if (args->uid < 1000) return;

        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name) {
            strncpy(g_process_name, nice_name, sizeof(g_process_name) - 1);
            // 识别媒体存储进程
            if (strstr(nice_name, "android.providers.media") || 
                strstr(nice_name, "android.process.media") ||
                strstr(nice_name, "com.google.android.providers.media")) {
                is_media_provider = true;
            }
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }

        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        int fd = api->connectCompanion();
        if (fd < 0) return;

        // 设置通讯超时
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char msg[512];
        if (is_media_provider) {
            // Media Provider 请求规则并上报
            snprintf(msg, sizeof(msg), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
        } else {
            // 普通应用仅上报，供后端执行 FUSE 注入
            snprintf(msg, sizeof(msg), "%s %d", g_process_name, getpid());
        }

        write(fd, msg, strlen(msg));

        // 接收来自 Companion (后端) 的指令
        char response[8192] = {0};
        ssize_t len = read(fd, response, sizeof(response) - 1);
        
        if (len > 0 && is_media_provider) {
            if (strncmp(response, "SET_RULES:", 10) == 0) {
                // 解析拦截规则
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                char* data = response + 10;
                char* token = strtok(data, ",");
                while (token) {
                    if (*token) g_block_rules.emplace_back(token);
                    token = strtok(nullptr, ",");
                }
                
                // 激活 Hook
                if (install_hooks()) {
                    g_hooks_active = true;
                    LOGI("媒体进程 Hook 注入成功，加载规则: %zu 条", g_block_rules.size());
                }
            }
        }
        
        close(fd);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    bool is_media_provider = false;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)