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
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>
#include <pthread.h>

#include "zygisk.hpp"

#define LOG_TAG "MEDIA_XP_INTERNAL_RAW_IO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {
    void __cxa_pure_virtual() { while (1); }
    int __cxa_guard_acquire(long long *g) { return !*(char *)(g); }
    void __cxa_guard_release(long long *g) { *(char *)g = 1; }
}

struct my_fuse_in_header {
    uint32_t len; uint32_t opcode; uint64_t unique; uint64_t nodeid;
    uint32_t uid; uint32_t gid; uint32_t pid; uint32_t padding;
};

static int (*orig_ioctl)(int fd, int request, void *arg);
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static ssize_t (*orig_read)(int fd, void *buf, size_t count);

static __thread uint32_t tl_uid = 0;
static __thread uint32_t tl_pid = 0;

struct my_binder_transaction_data_sg { struct binder_transaction_data tr; binder_size_t buffers_size; };
static const uint32_t CMD_BR_TRANSACTION_SG = _IOR('r', 17, struct my_binder_transaction_data_sg);
static const uint32_t CMD_BR_REPLY_SG = _IOR('r', 18, struct my_binder_transaction_data_sg);

static void scan_binder_parcel(void *buffer, size_t size, uint32_t cmd, struct binder_transaction_data *tr) {
    if (!buffer || size < 8) return;
    unsigned char *ptr = (unsigned char *)buffer;
    for (size_t i = 0; i < size - 8; i++) {
        if (ptr[i] == '/' || ptr[i] == 'c' || ptr[i] == 's') {
            char path[512] = {0}; size_t p = 0;
            bool is_u16 = (ptr[i+1] == 0);
            size_t step = is_u16 ? 2 : 1;
            size_t curr = i;
            while (curr < size && p < 511) {
                unsigned short c = is_u16 ? (ptr[curr] | (ptr[curr+1] << 8)) : ptr[curr];
                if (c == 0 || c < 32 || c > 126) break;
                path[p++] = (char)c; curr += step;
            }
            if (p > 10 && (strstr(path, "storage") || strstr(path, "content") || strstr(path, "media"))) {
                LOGI("[BINDER] Code:%u | CallerUID:%d | Info: %s", tr->code, tr->sender_euid, path);
                i = curr;
            }
        }
    }
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret = orig_read(fd, buf, count);
    if (ret >= (ssize_t)sizeof(struct my_fuse_in_header)) {
        struct my_fuse_in_header *h = (struct my_fuse_in_header *)buf;
        if (h->opcode > 0 && h->opcode < 100) { tl_uid = h->uid; tl_pid = h->pid; }
    }
    return ret;
}

static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    if (pathname && (strstr(pathname, "/data/media/") || strstr(pathname, "/storage/emulated/"))) {
        int fsuid = syscall(SYS_setfsuid, -1);
        uint32_t uid = (fsuid == (int)getuid() || fsuid < 0) ? tl_uid : (uint32_t)fsuid;
        LOGI("[FUSE-OPEN] Path: %s | User: %d | AppId: %d | PID: %u", pathname, uid / 100000, uid % 100000, tl_pid);
    }
    if (flags & O_CREAT) return orig_openat(dirfd, pathname, flags, mode);
    return orig_openat(dirfd, pathname, flags);
}

static int my_ioctl(int fd, int request, void *arg) {
    if (request != BINDER_WRITE_READ) return orig_ioctl(fd, request, arg);
    struct binder_write_read *bwr = (struct binder_write_read *)arg;
    int ret = orig_ioctl(fd, request, arg);
    if (ret >= 0 && bwr->read_consumed > 0) {
        unsigned char *p = (unsigned char *)bwr->read_buffer;
        unsigned char *end = p + bwr->read_consumed;
        while (p < end) {
            uint32_t cmd = *(uint32_t *)p; p += 4;
            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
                struct binder_transaction_data *tr = (struct binder_transaction_data *)p;
                if (tr->data_size > 0 && tr->data.ptr.buffer) scan_binder_parcel((void*)tr->data.ptr.buffer, tr->data_size, cmd, tr);
                p += sizeof(struct binder_transaction_data);
            } else if (cmd == CMD_BR_TRANSACTION_SG || cmd == CMD_BR_REPLY_SG) {
                struct my_binder_transaction_data_sg *sg = (struct my_binder_transaction_data_sg *)p;
                if (sg->tr.data_size > 0 && sg->tr.data.ptr.buffer) scan_binder_parcel((void*)sg->tr.data.ptr.buffer, sg->tr.data_size, cmd, &sg->tr);
                p += sizeof(struct my_binder_transaction_data_sg);
            } else { p += (_IOC_SIZE(cmd) + 3) & ~3; }
        }
    }
    return ret;
}

static void do_hook(zygisk::Api *api) {
    LOGI("开始执行 PLT Hook 扫描...");
    FILE *f = fopen("/proc/self/maps", "r"); if (!f) return;
    char line[512];
    int binder_hooked = 0, fuse_hooked = 0;
    while (fgets(line, sizeof(line), f)) {
        dev_t d; ino_t i; unsigned int ma, mi; unsigned long inv;
        if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &ma, &mi, &inv) != 3) continue;
        d = makedev(ma, mi); i = inv;
        if (strstr(line, "libbinder.so") && !binder_hooked) {
            api->pltHookRegister(d, i, "ioctl", (void *)my_ioctl, (void **)&orig_ioctl);
            binder_hooked = 1; LOGI("找到 libbinder.so, 准备 Hook");
        } else if ((strstr(line, "libmediaprovider_jni.so") || strstr(line, "libappfuse.so")) && !fuse_hooked) {
            api->pltHookRegister(d, i, "openat", (void *)my_openat, (void **)&orig_openat);
            api->pltHookRegister(d, i, "read", (void *)my_read, (void **)&orig_read);
            fuse_hooked = 1; LOGI("找到 FUSE 相关库, 准备 Hook");
        }
    }
    fclose(f); 
    if (api->pltHookCommit()) LOGI("PLT Hook 提交成功: Binder=%d, FUSE=%d", binder_hooked, fuse_hooked);
}

static void* heartbeat_worker(void* arg) {
    zygisk::Api* api = (zygisk::Api*)arg;
    for (int i = 0; i < 60; i++) {
        LOGI("[HEARTBEAT] MediaMonitor 存活. PID: %d, Count: %d", getpid(), i);
        if (i == 2) do_hook(api); // 延迟20秒二次尝试，防止库加载过慢
        sleep(10);
    }
    return nullptr;
}

class MediaMonitor : public zygisk::ModuleBase {
    zygisk::Api *api; JNIEnv *env; bool target = false;
public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override { api = a; env = e; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *n = env->GetStringUTFChars(args->nice_name, 0);
        if (n && strstr(n, "com.android.providers.media")) target = true;
        env->ReleaseStringUTFChars(args->nice_name, n);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (target) {
            LOGI("MediaProvider 注入成功，启动心跳线程");
            pthread_t tid;
            pthread_create(&tid, nullptr, heartbeat_worker, (void*)api);
            pthread_detach(tid);
            do_hook(api); 
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
