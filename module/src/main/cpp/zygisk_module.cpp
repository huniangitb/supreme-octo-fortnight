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

#include "zygisk.hpp"

#define LOG_TAG "MEDIA_XP_INTERNAL_RAW_IO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {
    void __cxa_pure_virtual() { while (1); }
    int __cxa_guard_acquire(long long *g) { return !*(char *)(g); }
    void __cxa_guard_release(long long *g) { *(char *)g = 1; }
}

static int (*orig_ioctl)(int fd, int request, void *arg);
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);

struct my_binder_transaction_data_sg { struct binder_transaction_data tr; binder_size_t buffers_size; };
static const uint32_t CMD_BR_TRANSACTION_SG = _IOR('r', 17, struct my_binder_transaction_data_sg);
static const uint32_t CMD_BR_REPLY_SG = _IOR('r', 18, struct my_binder_transaction_data_sg);

// 宽带 Binder 提取器
static void scan_binder_parcel(void *buffer, size_t size, uint32_t code) {
    if (!buffer || size < 8) return;
    unsigned char *ptr = (unsigned char *)buffer;
    for (size_t i = 0; i < size - 8; i++) {
        // 匹配常见开头的 UTF-16 或 UTF-8 字符串
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
            // 只要字符串够长，且包含核心要素，统统记录！
            if (p > 10 && (strstr(path, "storage") || strstr(path, "content") || strstr(path, "media"))) {
                LOGI("[BINDER] Code:%u | Extracted: %s", code, path);
                i = curr;
            }
        }
    }
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
                if (tr->data_size > 0 && tr->data.ptr.buffer) scan_binder_parcel((void*)tr->data.ptr.buffer, tr->data_size, tr->code);
                p += sizeof(struct binder_transaction_data);
            } else if (cmd == CMD_BR_TRANSACTION_SG || cmd == CMD_BR_REPLY_SG) {
                struct my_binder_transaction_data_sg *sg = (struct my_binder_transaction_data_sg *)p;
                if (sg->tr.data_size > 0 && sg->tr.data.ptr.buffer) scan_binder_parcel((void*)sg->tr.data.ptr.buffer, sg->tr.data_size, sg->tr.code);
                p += sizeof(struct my_binder_transaction_data_sg);
            } else { p += (_IOC_SIZE(cmd) + 3) & ~3; }
        }
    }
    return ret;
}

static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    
    // 关键修复：FUSE 操作大量使用相对路径 (如 "DCIM/abc.jpg")，根本没有 storage 前缀！
    // 过滤掉系统底层的噪音，放行并打印所有有价值的业务文件访问
    if (pathname && !strstr(pathname, "/dev/") && !strstr(pathname, "/proc/") && 
        !strstr(pathname, "/sys/") && !strstr(pathname, "/apex/")) {
        LOGI("[FILE-ACCESS] dirfd: %d | path: %s", dirfd, pathname);
    }

    if (flags & O_CREAT) return orig_openat(dirfd, pathname, flags, mode);
    return orig_openat(dirfd, pathname, flags);
}

// 必须完全在 postAppSpecialize 生命周期内同步执行
static void do_hook(zygisk::Api *api) {
    FILE *f = fopen("/proc/self/maps", "r"); 
    if (!f) return;
    char line[512];
    unsigned long hooked_inodes[256] = {0};
    int hooked_count = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned int ma, mi; unsigned long inv;
        if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &ma, &mi, &inv) != 3) continue;
        if (inv == 0) continue;

        bool already = false;
        for (int i = 0; i < hooked_count; i++) if (hooked_inodes[i] == inv) { already = true; break; }
        if (already) continue;

        dev_t d = makedev(ma, mi);

        // 地毯式挂钩：将所有可能负责 I/O 和 IPC 的底层库全部套上钩子
        if (strstr(line, "libbinder.so") || strstr(line, "libbinder_ndk.so") ||
            strstr(line, "libmediaprovider") || strstr(line, "libappfuse.so") ||
            strstr(line, "libfuse") || strstr(line, "libandroid_runtime.so") ||
            strstr(line, "libbase.so") || strstr(line, "libutils.so") || strstr(line, "libmedia.so")) {
            
            api->pltHookRegister(d, inv, "ioctl", (void *)my_ioctl, (void **)&orig_ioctl);
            api->pltHookRegister(d, inv, "openat", (void *)my_openat, (void **)&orig_openat);
            api->pltHookRegister(d, inv, "openat64", (void *)my_openat, (void **)&orig_openat);

            hooked_inodes[hooked_count++] = inv;
            
            // 清理并打印被挂钩的库名
            char* libname = strrchr(line, '/');
            if (libname) {
                char clean_name[64] = {0};
                sscanf(libname + 1, "%63s", clean_name);
                LOGI("注入目标库: %s (Inode: %lu)", clean_name, inv);
            }
        }
    }
    fclose(f);
    
    // 强制打印 Commit 返回值
    bool ret = api->pltHookCommit();
    LOGI("+++ PLT Hook 提交结果: %s +++", ret ? "SUCCESS" : "FAILED");
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
            LOGI("=== MediaProvider 挂钩程序启动 ===");
            // 立即同步执行，严禁放入任何延迟或后台线程！
            do_hook(api); 
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
