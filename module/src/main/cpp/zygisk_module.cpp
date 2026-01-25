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
    if (!new_path) return nullptr;
    
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
        }
    } else {
        LOGE("openat not found: %s", dlerror());
    }
    
    // 解析 mkdirat
    void *mkdirat_addr = dlsym(libc_handle, "mkdirat");
    if (mkdirat_addr) {
        if (DobbyHook(mkdirat_addr, (dobby_dummy_func_t)fake_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat) != 0) {
            LOGE("Failed to hook mkdirat");
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
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd);
        return;
    }

    // 检查锁文件
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        send_and_close("SKIP_NO_LOCK");
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {
        send_and_close("ERR_SOCKET_CREATE");
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        send_and_close("ERR_PROXY_CONN");
        return;
    }

    write(target_fd, buffer, strlen(buffer));
    
    char ack[16] = {0};
    struct timeval tv = {1, 0};
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t ack_len = read(target_fd, ack, sizeof(ack));
    write(client_fd, (ack_len > 0) ? ack : "OK_TIMEOUT", (ack_len > 0) ? (size_t)ack_len : 10);

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
        // 过滤 UID < 1001 的系统应用
        if (args->uid < 1001) {
            this->companion_fd = -1;
            return;
        }
        this->companion_fd = api->connectCompanion();
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();
        
        // 检查是否为媒体提供者进程
        if (process_name && strcmp(process_name, "com.android.providers.media.module") == 0) {
            LOGI("Detected media provider process");
            is_media_provider = true;
        }
        
        if (companion_fd >= 0) {
            // 设置 1 秒超时强制放行
            struct timeval tv = {1, 0};
            setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", getpid());
            
            write(companion_fd, buffer, strlen(buffer));

            char signal[32] = {0};
            // 阻塞直到信号返回或超时
            read(companion_fd, signal, sizeof(signal) - 1);
            close(companion_fd);
            companion_fd = -1;
        }
        
        // 仅在媒体提供者进程中安装 hook
        if (is_media_provider) {
            install_dobby_hooks();
        }
        
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd = -1;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)