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
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";
static const char* SOURCE_PATH = "/storage/emulated/0/Download/1DMP/";
static const char* TARGET_PATH = "/storage/emulated/0/Download/第三方下载/1DMP1/";

extern "C" const char* getprogname();

// Dobby Hook 相关函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);

// 仅在媒体提供者进程中安装 hook
static bool is_media_provider = false;

// 路径重定向核心函数
static char* redirect_path(const char *orig_path) {
    if (!orig_path || orig_path[0] != '/') return nullptr;
    
    // 检查是否匹配源路径
    if (strncmp(orig_path, SOURCE_PATH, strlen(SOURCE_PATH)) != 0) {
        return nullptr;
    }
    
    // 计算新路径长度 (目标路径 + 剩余部分 + 终止符)
    size_t suffix_len = strlen(orig_path) - strlen(SOURCE_PATH);
    size_t new_len = strlen(TARGET_PATH) + suffix_len + 1;
    
    // 路径过长保护
    if (new_len > PATH_MAX) {
        LOGE("Redirect path too long: %s", orig_path);
        return nullptr;
    }
    
    char *new_path = (char*)malloc(new_len);
    if (!new_path) {
        LOGE("Memory allocation failed for new path");
        return nullptr;
    }
    
    // 构造新路径
    snprintf(new_path, new_len, "%s%s", TARGET_PATH, orig_path + strlen(SOURCE_PATH));
    LOGI("Redirected: %s -> %s", orig_path, new_path);
    return new_path;
}

// Hook openat 函数
static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);

    char *new_path = redirect_path(pathname);
    int res;
    
    if (new_path) {
        if (flags & O_CREAT) {
            res = orig_openat(dirfd, new_path, flags, mode);
        } else {
            res = orig_openat(dirfd, new_path, flags);
        }
        free(new_path);
        return res;
    }
    
    // 未匹配路径，调用原始函数
    if (flags & O_CREAT) {
        return orig_openat(dirfd, pathname, flags, mode);
    }
    return orig_openat(dirfd, pathname, flags);
}

// Hook mkdirat 函数
static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    char *new_path = redirect_path(pathname);
    if (new_path) {
        int res = orig_mkdirat(dirfd, new_path, mode);
        free(new_path);
        return res;
    }
    return orig_mkdirat(dirfd, pathname, mode);
}

// 安装 Dobby Hook
static void install_dobby_hooks() {
    LOGI("Installing Dobby hooks for media provider");
    
    // 获取 libc 句柄
    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) {
        LOGE("Failed to open libc: %s", dlerror());
        return;
    }
    
    // 解析 openat
    void *openat_addr = dlsym(libc_handle, "openat");
    if (openat_addr) {
        if (DobbyHook(openat_addr, (dobby_dummy_func_t)fake_openat, (dobby_dummy_func_t*)&orig_openat) != 0) {
            LOGE("Failed to hook openat");
        } else {
            LOGI("Successfully hooked openat");
        }
    } else {
        LOGE("openat not found: %s", dlerror());
    }
    
    // 解析 mkdirat
    void *mkdirat_addr = dlsym(libc_handle, "mkdirat");
    if (mkdirat_addr) {
        if (DobbyHook(mkdirat_addr, (dobby_dummy_func_t)fake_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat) != 0) {
            LOGE("Failed to hook mkdirat");
        } else {
            LOGI("Successfully hooked mkdirat");
        }
    } else {
        LOGE("mkdirat not found: %s", dlerror());
    }
    
    dlclose(libc_handle);
}

static void companion_handler(int client_fd) {
    auto send_and_close = [&](const char* msg) {
        write(client_fd, msg, strlen(msg));
        close(client_fd);
    };

    char buffer[256] = {0};
    ssize_t read_len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (read_len <= 0) {
        LOGE("Read from client failed: %s", strerror(errno));
        close(client_fd);
        return;
    }
    buffer[read_len] = '\0';

    LOGI("Received from app: %s", buffer);

    // 检查锁文件
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        LOGI("Lock file not found, skipping hook");
        send_and_close("SKIP_NO_LOCK");
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        LOGE("Socket creation failed: %s", strerror(errno));
        send_and_close("ERR_SOCKET_CREATE");
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGE("Connection to backend failed: %s", strerror(errno));
        close(target_fd);
        send_and_close("ERR_PROXY_CONN");
        return;
    }

    LOGI("Successfully connected to backend socket");

    ssize_t write_len = write(target_fd, buffer, strlen(buffer));
    if (write_len != (ssize_t)strlen(buffer)) {
        LOGE("Partial/failed write to backend: %zd/%zu", write_len, strlen(buffer));
    } else {
        LOGI("Successfully sent data to backend");
    }
    
    char ack[16] = {0};
    struct timeval tv = {1, 0};
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t ack_len = read(target_fd, ack, sizeof(ack) - 1);
    if (ack_len > 0) {
        ack[ack_len] = '\0';
        LOGI("Received response from backend: %s", ack);
        write(client_fd, ack, ack_len);
    } else {
        LOGE("Read from backend failed or timed out: %s", strerror(errno));
        write(client_fd, "OK_TIMEOUT", 10);
    }

    close(target_fd);
    close(client_fd);
    LOGI("Companion handler completed");
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGI("Module loaded successfully");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 过滤 UID < 1001 的系统应用
        if (args->uid < 1001) {
            LOGI("Skipping system app with UID: %d", args->uid);
            this->companion_fd = -1;
            return;
        }
        
        LOGI("Connecting to companion for UID: %d", args->uid);
        this->companion_fd = api->connectCompanion();
        if (companion_fd < 0) {
            LOGE("Failed to connect to companion");
        }
        
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
    const char* process_name = nullptr;
    if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (!process_name) process_name = getprogname();
    
    pid_t pid = getpid();

    // 1. 【彻底旁路】如果是媒体存储进程，只装 Hook，不准碰任何 IPC
    if (process_name && (strcmp(process_name, "com.android.providers.media.module") == 0 || 
                         strcmp(process_name, "com.android.providers.media") == 0 ||
                         strstr(process_name, "android.process.media"))) {
        
        LOGI("Detected critical system process: %s. Applying Dobby Hook only, bypassing IPC.", process_name);
        install_dobby_hooks();
        
        // 释放内存并直接返回，不再执行下面的 companion 逻辑
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
        if (companion_fd >= 0) { close(companion_fd); companion_fd = -1; }
        return; 
    }

    // 2. 对于普通 App，执行原有的逻辑
    if (companion_fd >= 0) {
        // 设置极短的超时，防止 injector 挂了导致 App 卡死
        struct timeval tv = {0, 500000}; // 500ms
        setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char buffer[256];
        snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", pid);
        
        // 发送并快速读取（或者直接不读取，改为异步）
        write(companion_fd, buffer, strlen(buffer));
        
        char signal[32] = {0};
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