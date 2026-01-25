#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h> // 引入 pthread

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";
static const char* SOURCE_PATH = "/storage/emulated/0/Download/1DMP/";
static const char* TARGET_PATH = "/storage/emulated/0/Download/第三方下载/1DMP1/";

extern "C" const char* getprogname();

// Dobby Hook 相关函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);

// 防递归标志：每个线程独立
static thread_local bool g_is_hooking = false;

// 仅在媒体提供者进程中安装 hook
static bool is_media_provider = false;

// 路径重定向核心函数
static char* redirect_path(const char *orig_path) {
    if (!orig_path || orig_path[0] != '/') return nullptr;
    
    // 检查是否匹配源路径
    if (strncmp(orig_path, SOURCE_PATH, strlen(SOURCE_PATH)) != 0) {
        return nullptr;
    }
    
    // 计算新路径长度
    size_t suffix_len = strlen(orig_path) - strlen(SOURCE_PATH);
    size_t new_len = strlen(TARGET_PATH) + suffix_len + 1;
    
    if (new_len > PATH_MAX) return nullptr;
    
    char *new_path = (char*)malloc(new_len);
    if (!new_path) return nullptr;
    
    snprintf(new_path, new_len, "%s%s", TARGET_PATH, orig_path + strlen(SOURCE_PATH));
    // 注意：在这里打印日志可能是安全的，但也建议尽量减少
    return new_path;
}

// Hook openat 函数
static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    // 1. 获取可变参数 mode
    va_list ap;
    va_start(ap, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);

    // 2. 防递归检查：如果当前线程正在执行 Hook 逻辑，直接调用原函数
    if (g_is_hooking) {
        if (flags & O_CREAT) return orig_openat(dirfd, pathname, flags, mode);
        return orig_openat(dirfd, pathname, flags);
    }

    // 3. 标记进入 Hook
    g_is_hooking = true;
    
    int res;
    char *new_path = redirect_path(pathname);
    
    if (new_path) {
        LOGI("[Redirect] openat: %s -> %s", pathname, new_path);
        if (flags & O_CREAT) {
            res = orig_openat(dirfd, new_path, flags, mode);
        } else {
            res = orig_openat(dirfd, new_path, flags);
        }
        free(new_path);
    } else {
        // 未匹配路径
        if (flags & O_CREAT) {
            res = orig_openat(dirfd, pathname, flags, mode);
        } else {
            res = orig_openat(dirfd, pathname, flags);
        }
    }

    // 4. 标记退出 Hook
    g_is_hooking = false;
    return res;
}

// Hook mkdirat 函数
static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);

    g_is_hooking = true;
    
    int res;
    char *new_path = redirect_path(pathname);
    if (new_path) {
        LOGI("[Redirect] mkdirat: %s -> %s", pathname, new_path);
        res = orig_mkdirat(dirfd, new_path, mode);
        free(new_path);
    } else {
        res = orig_mkdirat(dirfd, pathname, mode);
    }
    
    g_is_hooking = false;
    return res;
}

static void install_dobby_hooks() {
    LOGI("Installing Dobby hooks (Protected)...");
    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) return;
    
    void *openat_addr = dlsym(libc_handle, "openat");
    if (openat_addr) {
        DobbyHook(openat_addr, (dobby_dummy_func_t)fake_openat, (dobby_dummy_func_t*)&orig_openat);
    }
    
    void *mkdirat_addr = dlsym(libc_handle, "mkdirat");
    if (mkdirat_addr) {
        DobbyHook(mkdirat_addr, (dobby_dummy_func_t)fake_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
    }
    dlclose(libc_handle);
}

static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t read_len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (read_len <= 0) {
        close(client_fd);
        return; // 客户端关闭或错误，直接结束，不打印 Error 以减少噪音
    }
    buffer[read_len] = '\0';

    // 检查锁文件
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        write(client_fd, "SKIP", 4); 
        close(client_fd);
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        close(client_fd);
        return;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        close(client_fd);
        return;
    }

    // 转发给 Injector
    write(target_fd, buffer, strlen(buffer));
    
    // 等待 Injector 简单回复 (避免阻塞太久)
    struct timeval tv = {1, 0}; // 1秒超时
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char ack[16] = {0};
    read(target_fd, ack, sizeof(ack) - 1);
    
    // 回复 App (让 App 知道流程结束，可以关闭 Socket 了)
    write(client_fd, "OK", 2);

    close(target_fd);
    close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 过滤系统应用 (UID < 10000 往往是系统服务，除了 media 相关的)
        if (args->uid < 1000) return;
        
        // 提前连接 Companion
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();
        
        pid_t pid = getpid();
        
        // --- 核心修复：针对 Media Provider 的处理 ---
        bool is_media = (process_name && (
            strcmp(process_name, "com.android.providers.media.module") == 0 || 
            strcmp(process_name, "com.android.providers.media") == 0 ||
            strstr(process_name, "android.process.media")
        ));

        if (is_media) {
            LOGI("System Process Detected: %s (PID %d). Hooking ONLY, No IPC.", process_name, pid);
            install_dobby_hooks(); // 安装带防递归保护的 Hook
            
            // 立即关闭 Companion 连接，绝对不发送数据
            if (companion_fd >= 0) {
                close(companion_fd);
                companion_fd = -1;
            }
            if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
            return;
        }
        
        // --- 普通 App 处理逻辑 ---
        if (companion_fd >= 0) {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", pid);
            
            // 发送数据
            write(companion_fd, buffer, strlen(buffer));
            
            // 等待 ACK，超时时间设为 200ms
            // 这确保 Companion 接收到了数据，且我们不会过早关闭导致 Bad File Descriptor
            struct timeval tv = {0, 200000}; 
            setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            char signal[16] = {0};
            read(companion_fd, signal, sizeof(signal) - 1);
            
            close(companion_fd);
            companion_fd = -1;
        }
        
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    int companion_fd = -1;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)