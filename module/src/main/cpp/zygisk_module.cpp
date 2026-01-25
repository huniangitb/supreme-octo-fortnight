#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
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
#include <cerrno>
#include <poll.h>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局状态 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};
static std::atomic<bool> g_hooks_active(false);

// --- 原始函数指针 (由 Dobby 回填) ---
static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

// --- 日志系统 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

// --- 路径拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    
    // 硬编码规则
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    
    // 动态规则
    if (g_block_rules.empty()) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- 代理函数 (Proxy Functions) ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Hook 安装逻辑 (Dobby) ---
static bool install_hooks() {
    z_log("正在使用 Dobby 初始化 Hooks...");

    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat || !sym_mkdirat) {
        if (!sym_openat) sym_openat = DobbySymbolResolver(nullptr, "openat");
        if (!sym_mkdirat) sym_mkdirat = DobbySymbolResolver(nullptr, "mkdirat");
    }

    if (!sym_openat || !sym_mkdirat) {
        z_log("致命错误：无法解析 openat 或 mkdirat 符号地址");
        return false;
    }

    int ret_open = DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
    int ret_mkdir = DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);

    if (ret_open == 0 && ret_mkdir == 0) {
        z_log("Dobby Hook 安装成功！");
        return true;
    } else {
        z_log("Dobby Hook 安装失败: open_ret=%d, mkdir_ret=%d", ret_open, ret_mkdir);
        return false;
    }
}

// --- 媒体存储设备：直接连接到后端服务 ---
static void setup_media_process() {
    z_log("开始设置媒体存储设备进程");
    
    // 直接连接到后端服务
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        z_log("创建socket失败: %s", strerror(errno));
        return;
    }
    
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        z_log("连接后端服务失败: %s", strerror(errno));
        close(fd);
        return;
    }
    
    // 发送REPORT消息
    char report[256];
    snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", g_process_name, getpid());
    if (write(fd, report, strlen(report)) <= 0) {
        z_log("发送REPORT失败: %s", strerror(errno));
        close(fd);
        return;
    }
    
    z_log("成功发送REPORT到后端服务");
    
    // 读取规则
    char buf[8192];
    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    if (len > 0) {
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
            z_log("规则更新: %zu 条", g_block_rules.size());
        }
    }
    
    close(fd);
    
    // 安装Hook（阻塞执行）
    if (install_hooks()) {
        g_hooks_active = true;
        z_log("媒体存储设备Hook已激活");
    }
}

// --- 普通应用：通过Companion汇报 ---
static void setup_normal_process() {
    z_log("开始设置普通应用进程");
    
    // 通过Companion汇报
    int fd = g_api->connectCompanion();
    if (fd < 0) {
        z_log("连接到Companion失败");
        return;
    }
    
    // 发送进程名称和PID
    char report[256];
    snprintf(report, sizeof(report), "%s %d", g_process_name, getpid());
    
    if (write(fd, report, strlen(report)) > 0) {
        z_log("成功发送进程信息到Companion");
        
        // 等待响应
        char response[64];
        ssize_t n = read(fd, response, sizeof(response)-1);
        if (n > 0) {
            response[n] = 0;
            z_log("Companion响应: %s", response);
        }
    } else {
        z_log("发送进程信息失败: %s", strerror(errno));
    }
    
    close(fd);
}

// --- Companion 逻辑（退回到旧式通讯）---
static void companion_handler(int client_fd) {
    char buf[256] = {0};
    ssize_t n = read(client_fd, buf, sizeof(buf)-1);
    
    if (n <= 0) {
        close(client_fd);
        return;
    }
    
    buf[n] = 0;
    
    // 连接到后端服务
    int backend_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (backend_fd < 0) {
        write(client_fd, "ERR:创建socket失败", 18);
        close(client_fd);
        return;
    }
    
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
    
    if (connect(backend_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "ERR:后端连接失败", 16);
        close(backend_fd);
        close(client_fd);
        return;
    }
    
    // 转发消息到后端
    if (write(backend_fd, buf, strlen(buf)) <= 0) {
        write(client_fd, "ERR:转发失败", 13);
        close(backend_fd);
        close(client_fd);
        return;
    }
    
    // 读取后端响应
    char response[64];
    ssize_t resp_len = read(backend_fd, response, sizeof(response)-1);
    if (resp_len > 0) {
        response[resp_len] = 0;
        write(client_fd, response, resp_len);
    } else {
        write(client_fd, "OK", 2);
    }
    
    close(backend_fd);
    close(client_fd);
}

// --- Zygisk 模块入口 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        g_api = api; 
        this->env = env; 
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name) {
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
            
            // 检查是否是媒体存储设备
            if (strstr(nice_name, "android.providers.media") || 
                strstr(nice_name, "android.process.media") ||
                strcmp(nice_name, "com.android.providers.media.module") == 0 ||
                strstr(nice_name, "com.google.android.providers.media")) {
                g_is_media_process = true;
            }
            
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 记录进程信息
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "进程注入: PID=%d, 名称=%s", getpid(), g_process_name);
        
        // 阻塞执行进程设置
        if (g_is_media_process) {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "媒体存储设备进程 - 开始设置");
            setup_media_process();
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "媒体存储设备进程 - 设置完成");
        } else {
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "普通应用进程 - 开始汇报");
            setup_normal_process();
            __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "普通应用进程 - 汇报完成");
        }
        
        // 关闭模块库
        g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)