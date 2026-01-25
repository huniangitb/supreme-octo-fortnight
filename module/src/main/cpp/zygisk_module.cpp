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

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";
static const char* SOURCE_PATH = "/storage/emulated/0/Download/1DMP/";
static const char* TARGET_PATH = "/storage/emulated/0/Download/第三方下载/1DMP1/";

extern "C" const char* getprogname();

// Dobby Hook 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);

// 防递归标志（重要：防止 Hook 函数内部调用系统函数导致死循环崩溃）
static thread_local bool g_is_hooking = false;

// 路径重定向逻辑
static char* redirect_path(const char *orig_path) {
    if (!orig_path || orig_path[0] != '/') return nullptr;
    if (strncmp(orig_path, SOURCE_PATH, strlen(SOURCE_PATH)) != 0) return nullptr;
    
    size_t suffix_len = strlen(orig_path) - strlen(SOURCE_PATH);
    size_t new_len = strlen(TARGET_PATH) + suffix_len + 1;
    if (new_len > PATH_MAX) return nullptr;
    
    char *new_path = (char*)malloc(new_len);
    if (!new_path) return nullptr;
    
    snprintf(new_path, new_len, "%s%s", TARGET_PATH, orig_path + strlen(SOURCE_PATH));
    return new_path;
}

// Hook 实现
static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) mode = va_arg(ap, mode_t);
    va_end(ap);

    if (g_is_hooking) {
        return (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);
    }

    g_is_hooking = true;
    int res;
    char *new_path = redirect_path(pathname);
    if (new_path) {
        LOGI("[Redirect] openat: %s", new_path);
        res = (flags & O_CREAT) ? orig_openat(dirfd, new_path, flags, mode) : orig_openat(dirfd, new_path, flags);
        free(new_path);
    } else {
        res = (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);
    }
    g_is_hooking = false;
    return res;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);

    g_is_hooking = true;
    int res;
    char *new_path = redirect_path(pathname);
    if (new_path) {
        LOGI("[Redirect] mkdirat: %s", new_path);
        res = orig_mkdirat(dirfd, new_path, mode);
        free(new_path);
    } else {
        res = orig_mkdirat(dirfd, pathname, mode);
    }
    g_is_hooking = false;
    return res;
}

static void install_hooks() {
    LOGI("Installing MediaProvider hooks...");
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return;
    
    void *openat_ptr = dlsym(handle, "openat");
    void *mkdirat_ptr = dlsym(handle, "mkdirat");
    
    if (openat_ptr) DobbyHook(openat_ptr, (dobby_dummy_func_t)fake_openat, (dobby_dummy_func_t*)&orig_openat);
    if (mkdirat_ptr) DobbyHook(mkdirat_ptr, (dobby_dummy_func_t)fake_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
    
    dlclose(handle);
    LOGI("Hooks installed successfully.");
}

// Companion 处理
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t read_len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (read_len <= 0) {
        close(client_fd);
        return;
    }
    buffer[read_len] = '\0';

    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        write(client_fd, "SKIP_NO_LOCK", 12);
        close(client_fd);
        return;
    }

    // 满足条件 3: 添加 SOCK_CLOEXEC
    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        write(client_fd, "ERR_SOCK", 8);
        close(client_fd);
        return;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        write(client_fd, "ERR_CONN", 8);
        close(client_fd);
        return;
    }

    // 转发给 Injector 进程
    write(target_fd, buffer, strlen(buffer));
    
    // 等待简单 ACK 确保 Injector 已接收
    struct timeval tv = {0, 500000}; // 500ms 超时
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char ack[8] = {0};
    read(target_fd, ack, sizeof(ack) - 1);
    
    // 回复 Zygisk Module
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
        // 满足条件 1: UID < 10000 过滤
        if (args->uid < 10000) {
            this->companion_fd = -1;
            return;
        }
        
        // 满足条件 2: 移除强制卸载和库卸载选项
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();
        
        pid_t pid = getpid();

        // 特殊进程判断
        bool is_media = (process_name && (
            strcmp(process_name, "com.android.providers.media.module") == 0 || 
            strcmp(process_name, "com.android.providers.media") == 0 ||
            strstr(process_name, "android.process.media")
        ));

        if (is_media) {
            LOGI("Media process specialized: %s (PID: %d). Installing Hook, bypassing IPC.", process_name, pid);
            install_hooks();
            
            // 如果是 media 进程，即使 UID > 10000 也要关闭 IPC 通信防止干扰启动
            if (companion_fd >= 0) {
                close(companion_fd);
                companion_fd = -1;
            }
        } else if (companion_fd >= 0) {
            // 普通 App 上报
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", pid);
            
            write(companion_fd, buffer, strlen(buffer));
            
            // 等待反馈防止 Socket 过早关闭导致的 Bad File Descriptor
            struct timeval tv = {0, 300000}; 
            setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            char ack[8] = {0};
            read(companion_fd, ack, sizeof(ack) - 1);
            
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