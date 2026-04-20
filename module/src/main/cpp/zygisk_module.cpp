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
#include <sys/sysmacros.h> // 必须包含：解决 makedev 报错
#include <linux/android/binder.h>

#include "zygisk.hpp"

#define LOG_TAG "MEDIA_STORAGE_SPY"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ABI 兼容桩：解决断开 libc++ 链接后的符号缺失
extern "C" {
    void __cxa_pure_virtual() { while (1); }
    int __cxa_guard_acquire(long long *g) { return !*(char *)(g); }
    void __cxa_guard_release(long long *g) { *(char *)g = 1; }
}

// 模拟 FUSE 内核协议头
struct my_fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

// 线程本地存储：捕获 FUSE 事务中的调用者上下文
static __thread struct {
    uint32_t uid;
    uint32_t pid;
} last_caller = {0, 0};

static ssize_t (*orig_readv)(int fd, const struct iovec *iov, int iovcnt);
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);

// 拦截 FUSE 消息读取：这是识别全局 App UserId 的唯一靠谱路径
static ssize_t my_readv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    if (ret >= (ssize_t)sizeof(struct my_fuse_in_header) && iovcnt > 0 && iov[0].iov_base) {
        struct my_fuse_in_header *hdr = (struct my_fuse_in_header *)iov[0].iov_base;
        // 过滤合法范围内的 OpCode (FUSE_OPEN=14, FUSE_CREATE=35, 等)
        if (hdr->opcode > 0 && hdr->opcode < 100) {
            last_caller.uid = hdr->uid;
            last_caller.pid = hdr->pid;
        }
    }
    return ret;
}

// 拦截底层物理文件 openat
static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }

    if (pathname && !strstr(pathname, "/dev/") && !strstr(pathname, "/proc/")) {
        // 身份回溯：优先使用 FUSE 捕获的 UID，备选使用 fsuid
        uint32_t uid = last_caller.uid;
        if (uid == 0) {
            int fsuid = syscall(SYS_setfsuid, -1);
            uid = (fsuid >= 0) ? (uint32_t)fsuid : getuid();
        }

        // 排除 MediaProvider 自身（UID 1000 以内或自身 UID）的噪音
        if (uid >= 10000) {
            LOGI("[FUSE-MON] User:%u | AppId:%u | PID:%u | Path:%s", 
                 uid / 100000, uid % 100000, last_caller.pid, pathname);
        }
    }

    return (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);
}

static void do_hook(zygisk::Api *api) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    unsigned long hooked_inodes[128] = {0};
    int hooked_count = 0;

    while (fgets(line, sizeof(line), f)) {
        // 仅 Hook 具备执行权限的代码段
        if (!strstr(line, "r-xp")) continue;

        // 针对 Android 13+ 的地毯式扫描：锁定 MediaProvider APEX 核心库
        if (!strstr(line, "/apex/com.android.mediaprovider") && 
            !strstr(line, "libmediaprovider") &&
            !strstr(line, "libappfuse.so")) continue;

        unsigned int ma, mi; unsigned long inv;
        if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &ma, &mi, &inv) == 3 && inv > 0) {
            bool dup = false;
            for (int i = 0; i < hooked_count; i++) if (hooked_inodes[i] == inv) { dup = true; break; }
            if (dup) continue;

            dev_t d = makedev(ma, mi);
            api->pltHookRegister(d, inv, "readv", (void *)my_readv, (void **)&orig_readv);
            api->pltHookRegister(d, inv, "openat", (void *)my_openat, (void **)&orig_openat);
            api->pltHookRegister(d, inv, "openat64", (void *)my_openat, (void **)&orig_openat);
            
            if (hooked_count < 128) hooked_inodes[hooked_count++] = inv;
        }
    }
    fclose(f);
    api->pltHookCommit();
    LOGI("+++ MediaProvider FUSE 身份追踪钩子已部署 +++");
}

class MediaMonitor : public zygisk::ModuleBase {
    zygisk::Api *api;
    JNIEnv *env;
    bool is_mp = false;
public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override { api = a; env = e; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *name = env->GetStringUTFChars(args->nice_name, 0);
        if (name) {
            if (strstr(name, "com.android.providers.media")) is_mp = true;
            env->ReleaseStringUTFChars(args->nice_name, name);
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (is_mp) {
            do_hook(api);
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
