#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <android/log.h>
#include <stdlib.h>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 全局状态 ---
static char** g_block_rules = NULL;
static size_t g_block_rules_count = 0;
static pthread_mutex_t g_rule_mutex = PTHREAD_MUTEX_INITIALIZER;
static zygisk::Api* g_api = NULL;
static bool g_is_media_process = false;
static char g_process_name[256] = "unknown";
static volatile int g_hooks_active = 0;

// --- 原始函数指针 (由 Dobby 回填) ---
static int (*orig_openat)(int, const char*, int, mode_t) = NULL;
static int (*orig_mkdirat)(int, const char*, mode_t) = NULL;

// --- 日志系统 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

// --- 动态规则管理 ---
static void add_block_rule(const char* rule) {
    pthread_mutex_lock(&g_rule_mutex);
    
    // 重新分配内存
    char** new_rules = (char**)realloc(g_block_rules, (g_block_rules_count + 1) * sizeof(char*));
    if (!new_rules) {
        pthread_mutex_unlock(&g_rule_mutex);
        return;
    }
    
    g_block_rules = new_rules;
    g_block_rules[g_block_rules_count] = strdup(rule);
    if (g_block_rules[g_block_rules_count]) {
        g_block_rules_count++;
    }
    
    pthread_mutex_unlock(&g_rule_mutex);
}

static void clear_block_rules(void) {
    pthread_mutex_lock(&g_rule_mutex);
    
    for (size_t i = 0; i < g_block_rules_count; i++) {
        free(g_block_rules[i]);
    }
    free(g_block_rules);
    g_block_rules = NULL;
    g_block_rules_count = 0;
    
    pthread_mutex_unlock(&g_rule_mutex);
}

// --- 路径拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    
    // 硬编码规则
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    
    // 动态规则
    pthread_mutex_lock(&g_rule_mutex);
    
    bool blocked = false;
    for (size_t i = 0; i < g_block_rules_count; i++) {
        if (strstr(path, g_block_rules[i])) {
            blocked = true;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_rule_mutex);
    return blocked;
}

// --- 代理函数 (Proxy Functions) ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (__atomic_load_n(&g_hooks_active, __ATOMIC_ACQUIRE) && is_path_blocked(path)) {
        z_log("BLOCKED openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (__atomic_load_n(&g_hooks_active, __ATOMIC_ACQUIRE) && is_path_blocked(path)) {
        z_log("BLOCKED mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Hook 安装逻辑 (Dobby) ---
static bool install_hooks(void) {
    z_log("正在使用 Dobby 初始化 Hooks...");

    void* sym_openat = DobbySymbolResolver("libc.so", "openat");
    void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");

    if (!sym_openat || !sym_mkdirat) {
        if (!sym_openat) sym_openat = DobbySymbolResolver(NULL, "openat");
        if (!sym_mkdirat) sym_mkdirat = DobbySymbolResolver(NULL, "mkdirat");
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

// --- 解析规则字符串 ---
static void parse_rules_string(const char* rules_str) {
    if (!rules_str || !*rules_str) return;
    
    clear_block_rules();
    
    char* str = strdup(rules_str);
    if (!str) return;
    
    char* saveptr = NULL;
    char* token = strtok_r(str, ",", &saveptr);
    
    while (token) {
        if (*token) {
            add_block_rule(token);
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(str);
    z_log("规则更新: %zu 条", g_block_rules_count);
}

// --- 媒体存储设备：直接连接到后端服务 ---
static void setup_media_process(void) {
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
            parse_rules_string(buf + 10);
        }
    }
    
    close(fd);
    
    // 安装Hook（阻塞执行）
    if (install_hooks()) {
        __atomic_store_n(&g_hooks_active, 1, __ATOMIC_RELEASE);
        z_log("媒体存储设备Hook已激活");
    }
}

// --- 普通应用：通过Companion汇报 ---
static void setup_normal_process(void) {
    z_log("开始设置普通应用进程");
    
    if (!g_api) {
        z_log("错误: g_api 未初始化");
        return;
    }
    
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
        const char* err_msg = "ERR:创建socket失败";
        write(client_fd, err_msg, strlen(err_msg));
        close(client_fd);
        return;
    }
    
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
    
    if (connect(backend_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        const char* err_msg = "ERR:后端连接失败";
        write(client_fd, err_msg, strlen(err_msg));
        close(backend_fd);
        close(client_fd);
        return;
    }
    
    // 转发消息到后端
    if (write(backend_fd, buf, strlen(buf)) <= 0) {
        const char* err_msg = "ERR:转发失败";
        write(client_fd, err_msg, strlen(err_msg));
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
        const char* ok_msg = "OK";
        write(client_fd, ok_msg, strlen(ok_msg));
    }
    
    close(backend_fd);
    close(client_fd);
}

// --- Zygisk 模块入口 ---
static JNIEnv* g_env = NULL;

class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        g_api = api; 
        g_env = env; 
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = NULL;
        if (args->nice_name) nice_name = g_env->GetStringUTFChars(args->nice_name, NULL);
        
        if (nice_name) {
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
            g_process_name[sizeof(g_process_name)-1] = '\0';
            
            // 检查是否是媒体存储设备
            if (strstr(nice_name, "android.providers.media") || 
                strstr(nice_name, "android.process.media") ||
                strcmp(nice_name, "com.android.providers.media.module") == 0 ||
                strstr(nice_name, "com.google.android.providers.media")) {
                g_is_media_process = true;
            }
            
            g_env->ReleaseStringUTFChars(args->nice_name, nice_name);
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
};

extern "C" {
    REGISTER_ZYGISK_MODULE(MediaTargetModule)
    REGISTER_ZYGISK_COMPANION(companion_handler)
}