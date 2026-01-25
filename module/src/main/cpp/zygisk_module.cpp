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
#include <dirent.h>
#include <sys/syscall.h>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

// 路径定义：确保物理磁盘上只有 TARGET_BASE，没有 SOURCE_BASE
static const char* SOURCE_BASE = "/storage/emulated/0/Download/1DMP";
static const char* SOURCE_NAME = "1DMP";
static const char* TARGET_BASE = "/storage/emulated/0/Download/第三方下载/1DMP";
static const char* PARENT_DIR = "/storage/emulated/0/Download";

extern "C" const char* getprogname();

// 结构定义用于 getdents64
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

// 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags);
static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags);
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

static thread_local bool g_is_hooking = false;

// 路径规范化与重定向
static char* redirect_path(const char *orig_path) {
    if (!orig_path || orig_path[0] != '/') return nullptr;
    if (!strstr(orig_path, "1DMP")) return nullptr;

    char temp[PATH_MAX];
    strncpy(temp, orig_path, PATH_MAX - 1);
    temp[PATH_MAX - 1] = '\0';
    size_t len = strlen(temp);
    while (len > 1 && temp[len - 1] == '/') { temp[len - 1] = '\0'; len--; }

    // 精确匹配父目录或其子项
    if (strcmp(temp, SOURCE_BASE) == 0) return strdup(TARGET_BASE);
    size_t src_len = strlen(SOURCE_BASE);
    if (strncmp(temp, SOURCE_BASE, src_len) == 0 && temp[src_len] == '/') {
        char* new_path = (char*)malloc(PATH_MAX);
        snprintf(new_path, PATH_MAX, "%s%s", TARGET_BASE, temp + src_len);
        return new_path;
    }
    return nullptr;
}

// --- Syscall Hooks ---

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = 0; if (flags & O_CREAT) mode = va_arg(ap, mode_t);
    va_end(ap);
    if (g_is_hooking) return (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);
    g_is_hooking = true;
    char *new_path = redirect_path(pathname);
    int res = (flags & O_CREAT) ? orig_openat(dirfd, new_path ? new_path : pathname, flags, mode) : orig_openat(dirfd, new_path ? new_path : pathname, flags);
    if (new_path) free(new_path);
    g_is_hooking = false;
    return res;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);
    g_is_hooking = true;
    char *new_path = redirect_path(pathname);
    int res = orig_mkdirat(dirfd, new_path ? new_path : pathname, mode);
    if (new_path) { LOGI("[Virtual] Redirected mkdir %s to physical 1DMP1", pathname); free(new_path); }
    g_is_hooking = false;
    return res;
}

static int fake_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (g_is_hooking) return orig_faccessat(dirfd, pathname, mode, flags);
    g_is_hooking = true;
    char *new_path = redirect_path(pathname);
    int res = orig_faccessat(dirfd, new_path ? new_path : pathname, mode, flags);
    if (new_path) free(new_path);
    g_is_hooking = false;
    return res;
}

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    g_is_hooking = true;
    char *new_path = redirect_path(pathname);
    int res = orig_fstatat(dirfd, new_path ? new_path : pathname, buf, flags);
    if (new_path) free(new_path);
    g_is_hooking = false;
    return res;
}

// 核心功能：使 1DMP 在目录列表中不可见
static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0 || g_is_hooking) return nread;

    g_is_hooking = true;
    char path[PATH_MAX];
    char procfd[64];
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    
    // 只在 Download 目录下执行过滤逻辑，减少性能损耗
    if (readlink(procfd, path, PATH_MAX) > 0 && strstr(path, "Download")) {
        for (int bpos = 0; bpos < nread; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) ((char *)dirp + bpos);
            if (strcmp(d->d_name, SOURCE_NAME) == 0) {
                // 发现 1DMP，通过挪动后续数据将其从 buffer 中抹去
                int rest = nread - (bpos + d->d_reclen);
                if (rest > 0) {
                    memmove(d, (char *)d + d->d_reclen, rest);
                }
                nread -= d->d_reclen;
                continue; // 继续检查，防止重复项
            }
            bpos += d->d_reclen;
        }
    }
    g_is_hooking = false;
    return nread;
}

static void install_hooks() {
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return;
    
    #define DO_HOOK(name) \
        void *ptr_##name = dlsym(handle, #name); \
        if (ptr_##name) DobbyHook(ptr_##name, (dobby_dummy_func_t)fake_##name, (dobby_dummy_func_t*)&orig_##name)

    DO_HOOK(openat);
    DO_HOOK(mkdirat);
    DO_HOOK(faccessat);
    DO_HOOK(fstatat);
    DO_HOOK(getdents64); // 隐藏目录项的关键

    dlclose(handle);
    LOGI("Virtual FS Shield Installed: 1DMP is now invisible and redirected.");
}

// --- Zygisk / Companion 逻辑 (保持要求：UID < 10000, SOCK_CLOEXEC) ---

static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    if (read(client_fd, buffer, sizeof(buffer) - 1) <= 0) { close(client_fd); return; }
    if (access(LOCK_FILE_PATH, F_OK) != 0) { close(client_fd); return; }

    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); // 条件 3
    if (target_fd < 0) { close(client_fd); return; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        write(target_fd, buffer, strlen(buffer));
        struct timeval tv = {0, 500000};
        setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char ack[8] = {0}; read(target_fd, ack, sizeof(ack) - 1);
        write(client_fd, "OK", 2);
    }
    close(target_fd); close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { this->api = api; this->env = env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) { this->companion_fd = -1; return; } // 条件 1
        this->companion_fd = api->connectCompanion(); // 条件 2: 移除了 FORCE_DENYLIST 选项
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();
        
        bool is_media = (process_name && (
            strstr(process_name, "com.android.providers.media") || 
            strstr(process_name, "android.process.media")
        ));

        if (is_media) {
            install_hooks();
            if (companion_fd >= 0) { close(companion_fd); companion_fd = -1; }
        } else if (companion_fd >= 0) {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", (int)getpid());
            write(companion_fd, buffer, strlen(buffer));
            struct timeval tv = {0, 300000};
            setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            char ack[8] = {0}; read(companion_fd, ack, sizeof(ack) - 1);
            close(companion_fd);
        }
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    zygisk::Api *api = nullptr; JNIEnv *env = nullptr; int companion_fd = -1;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)