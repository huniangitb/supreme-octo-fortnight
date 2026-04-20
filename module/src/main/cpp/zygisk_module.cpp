#include <jni.h>
#include <android/log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <linux/android/binder.h>

#include "zygisk.hpp"

#define LOG_TAG "MEDIA_STORAGE_SPY"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ABI 兼容桩
extern "C" {
    void __cxa_pure_virtual() { while (1); }
    int __cxa_guard_acquire(long long *g) { return !*(char *)(g); }
    void __cxa_guard_release(long long *g) { *(char *)g = 1; }
}

// 标准 FUSE 请求头
struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

// 线程本地存储：缓存当前 FUSE 处理循环中的调用者身份
static __thread struct {
    uint32_t uid;
    uint32_t pid;
    uint32_t opcode;
} current_caller = {0, 0, 0};

static ssize_t (*orig_readv)(int fd, const struct iovec *iov, int iovcnt);
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);

// 解析 FUSE 协议封包
static void parse_fuse_buffer(void* base, size_t len) {
    if (len >= sizeof(struct fuse_in_header)) {
        struct fuse_in_header *hdr = (struct fuse_in_header *)base;
        // 过滤常见的 FUSE 操作：LOOKUP(1), OPEN(14), CREATE(35), MKDIR(9)
        if (hdr->opcode >= 1 && hdr->opcode <= 50) {
            current_caller.uid = hdr->uid;
            current_caller.pid = hdr->pid;
            current_caller.opcode = hdr->opcode;
        }
    }
}

// 拦截 FUSE 消息读取
static ssize_t my_readv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    if (ret > 0 && iovcnt > 0 && iov[0].iov_base) {
        parse_fuse_buffer(iov[0].iov_base, iov[0].iov_len);
    }
    return ret;
}

// 拦截物理文件打开
static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }

    if (pathname && !strstr(pathname, "/dev/") && !strstr(pathname, "/proc/")) {
        uint32_t uid = current_caller.uid;
        // 如果 FUSE 没抓到，回退到 setfsuid 探测
        if (uid == 0) uid = syscall(SYS_setfsuid, -1);
        if (uid == getuid()) uid = 0; // 忽略 MediaProvider 自身的扫描操作

        if (uid > 0) {
            int user_id = uid / 100000;
            int app_id = uid % 100000;
            LOGI("[OPEN] User:%d | App:%d | PID:%u | Path:%s", 
                 user_id, app_id, current_caller.pid, pathname);
        }
    }

    return (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);
}

static void do_hook(zygisk::Api *api) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    
    while (fgets(line, sizeof(line), f)) {
        // 关键：在 Android 13 中，代码可能在 .apk 映射内，也可能在解压后的 .so 
        if (!strstr(line, "r-xp")) continue;
        if (!strstr(line, "/apex/com.android.mediaprovider") && 
            !strstr(line, "libmediaprovider") &&
            !strstr(line, "libappfuse.so")) continue;

        unsigned int ma, mi; unsigned long inv;
        if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &ma, &mi, &inv) == 3) {
            dev_t d = makedev(ma, mi);
            api->pltHookRegister(d, inv, "readv", (void *)my_readv, (void **)&orig_readv);
            api->pltHookRegister(d, inv, "openat", (void *)my_openat, (void **)&orig_openat);
            api->pltHookRegister(d, inv, "openat64", (void *)my_openat, (void **)&orig_openat);
        }
    }
    fclose(f);
    api->pltHookCommit();
}

class MediaMonitor : public zygisk::ModuleBase {
    zygisk::Api *api; JNIEnv *env; bool is_mp = false;
public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override { api = a; env = e; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *name = env->GetStringUTFChars(args->nice_name, 0);
        if (name && strstr(name, "com.android.providers.media")) is_mp = true;
        env->ReleaseStringUTFChars(args->nice_name, name);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (is_mp) {
            LOGI("MediaProvider 拦截器激活...");
            do_hook(api);
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
