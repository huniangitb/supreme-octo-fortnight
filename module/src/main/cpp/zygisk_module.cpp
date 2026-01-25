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

// 注意：规则路径末尾不要写斜杠，逻辑中会自动处理边界
static const char* SOURCE_BASE = "/storage/emulated/0/Download/1DMP";
static const char* TARGET_BASE = "/storage/emulated/0/Download/第三方下载/1DMP1";

extern "C" const char* getprogname();

// Dobby Hook 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);

// 防递归标志
static thread_local bool g_is_hooking = false;

// 路径重定向逻辑：末尾是否有斜杠都视为同一个
static char* redirect_path(const char *orig_path) {
    if (!orig_path || orig_path[0] != '/') return nullptr;

    // 1. 复制一份路径用于规范化处理
    char temp_path[PATH_MAX];
    strncpy(temp_path, orig_path, PATH_MAX - 1);
    temp_path[PATH_MAX - 1] = '\0';

    // 2. 去掉末尾斜杠 (例如 /abc/ -> /abc)
    size_t len = strlen(temp_path);
    while (len > 1 && temp_path[len - 1] == '/') {
        temp_path[len - 1] = '\0';
        len--;
    }

    size_t src_len = strlen(SOURCE_BASE);

    // 情况 A: 路径完全匹配父目录 (去掉斜杠后一致)
    if (strcmp(temp_path, SOURCE_BASE) == 0) {
        return strdup(TARGET_BASE);
    }

    // 情况 B: 路径是子目录或子文件 (例如 /SOURCE_BASE/file)
    // 检查是否以 SOURCE_BASE/ 为前缀
    if (strncmp(temp_path, SOURCE_BASE, src_len) == 0 && temp_path[src_len] == '/') {
        const char* suffix = temp_path + src_len; // 包含领头的斜杠
        size_t target_len = strlen(TARGET_BASE) + strlen(suffix) + 1;
        char* new_path = (char*)malloc(target_len);
        if (new_path) {
            snprintf(new_path, target_len, "%s%s", TARGET_BASE, suffix);
        }
        return new_path;
    }

    return nullptr;
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
        LOGI("[Redirect] openat: %s -> %s", pathname, new_path);
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
        LOGI("[Redirect] mkdirat: %s -> %s", pathname, new_path);
        res = orig_mkdirat(dirfd, new_path, mode);
        free(new_path);
    } else {
        res = orig_mkdirat(dirfd, pathname, mode);
    }
    g_is_hooking = false;
    return res;
}

static void install_hooks() {
    LOGI("Installing MediaProvider hooks (Normalized Path Mode)...");
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return;
    
    void *openat_ptr = dlsym(handle, "openat");
    void *mkdirat_ptr = dlsym(handle, "mkdirat");
    
    if (openat_ptr) DobbyHook(openat_ptr, (dobby_dummy_func_t)fake_openat, (dobby_dummy_func_t*)&orig_openat);
    if (mkdirat_ptr) DobbyHook(mkdirat_ptr, (dobby_dummy_func_t)fake_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
    
    dlclose(handle);
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
        close(client_fd);
        return;
    }

    // 满足条件 3: 使用 SOCK_CLOEXEC
    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        close(client_fd);
        return;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        close(client_fd);
        return;
    }

    write(target_fd, buffer, strlen(buffer));
    
    // 等待 ACK 确保同步
    struct timeval tv = {0, 500000}; 
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char ack[8] = {0};
    read(target_fd, ack, sizeof(ack) - 1);
    
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
        
        // 满足条件 2: 不设置 FORCE_DENYLIST_UNMOUNT / DLCLOSE
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();
        
        pid_t pid = getpid();

        // 识别媒体核心进程
        bool is_media = (process_name && (
            strcmp(process_name, "com.android.providers.media.module") == 0 || 
            strcmp(process_name, "com.android.providers.media") == 0 ||
            strstr(process_name, "android.process.media")
        ));

        if (is_media) {
            LOGI("Media process specialized: %s (PID: %d). Installing Path-Normalized Hook.", process_name, pid);
            install_hooks();
            
            if (companion_fd >= 0) {
                close(companion_fd);
                companion_fd = -1;
            }
        } else if (companion_fd >= 0) {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", pid);
            
            write(companion_fd, buffer, strlen(buffer));
            
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