#include <jni.h>
#include <android/log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>

#include "zygisk.hpp"

#define LOG_TAG "MEDIA_XP_INTERNAL_RAW_IO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {
    void __cxa_pure_virtual() { while (1); }
}

static int (*orig_ioctl)(int fd, int request, void *arg);

struct my_binder_transaction_data_sg {
    struct binder_transaction_data tr;
    binder_size_t buffers_size;
};

static const uint32_t CMD_BR_TRANSACTION_SG = _IOR('r', 17, struct my_binder_transaction_data_sg);
static const uint32_t CMD_BR_REPLY_SG = _IOR('r', 18, struct my_binder_transaction_data_sg);

// 宽带特征扫描器：抛弃死板的等长路径匹配，动态提取所有可能与存储相关的字符串
static void scan_parcel_wide(void *buffer, size_t size, uint32_t cmd, uint32_t code) {
    if (!buffer || size < 16) return;
    unsigned char *ptr = (unsigned char *)buffer;

    // 1. 扫描 UTF-16 (标准的 Android Parcel 字符串)
    for (size_t i = 0; i < size - 10; i += 2) {
        // 通常以 / (路径), c (content), s (storage) 开头
        if (ptr[i] == '/' || ptr[i] == 'c' || ptr[i] == 's') {
            char buf[512] = {0};
            size_t p = 0;
            size_t curr = i;
            
            while (curr + 1 < size && p < 511) {
                unsigned short c = ptr[curr] | (ptr[curr+1] << 8);
                if (c == 0 || c < 32 || c > 126) break;
                buf[p++] = (char)c;
                curr += 2;
            }
            
            // 提取长度大于 8，且包含存储核心关键词的字符串
            if (p > 8 && (strstr(buf, "storage") || strstr(buf, "media") || strstr(buf, "content"))) {
                LOGI("[Binder|C:%u] [UTF-16] %s", code, buf);
                i = curr; 
            }
        }
    }

    // 2. 扫描 UTF-8 (Android 11+ Uri.writeToParcel 采用了 String8 优化)
    for (size_t i = 0; i < size - 8; i++) {
        if (ptr[i] == '/' || ptr[i] == 'c' || ptr[i] == 's') {
            char buf[512] = {0};
            size_t p = 0;
            
            while (i + p < size && p < 511) {
                unsigned char c = ptr[i+p];
                if (c == 0 || c < 32 || c > 126) break;
                buf[p++] = (char)c;
            }
            
            if (p > 8 && (strstr(buf, "storage") || strstr(buf, "media") || strstr(buf, "content"))) {
                LOGI("[Binder|C:%u] [UTF-8 ] %s", code, buf);
                i += p; 
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
            uint32_t cmd = *(uint32_t *)p;
            p += 4;

            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
                struct binder_transaction_data *tr = (struct binder_transaction_data *)p;
                if (tr->data_size > 0 && tr->data.ptr.buffer) {
                    scan_parcel_wide((void *)tr->data.ptr.buffer, tr->data_size, cmd, tr->code);
                }
                p += sizeof(struct binder_transaction_data);
            } 
            else if (cmd == CMD_BR_TRANSACTION_SG || cmd == CMD_BR_REPLY_SG) {
                struct my_binder_transaction_data_sg *tr_sg = (struct my_binder_transaction_data_sg *)p;
                if (tr_sg->tr.data_size > 0 && tr_sg->tr.data.ptr.buffer) {
                    scan_parcel_wide((void *)tr_sg->tr.data.ptr.buffer, tr_sg->tr.data_size, cmd, tr_sg->tr.code);
                }
                p += sizeof(struct my_binder_transaction_data_sg);
            } 
            else {
                p += (_IOC_SIZE(cmd) + 3) & ~3;
            }
        }
    }
    return ret;
}

static bool get_lib_info(const char *name, dev_t *dev, ino_t *ino) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            unsigned int ma, mi; unsigned long inv;
            if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &ma, &mi, &inv) == 3) {
                *dev = makedev(ma, mi); *ino = inv;
                fclose(f); return true;
            }
        }
    }
    fclose(f); return false;
}

class MediaMonitor : public zygisk::ModuleBase {
    zygisk::Api *api; JNIEnv *env; bool target = false;
public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override { api = a; env = e; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args->nice_name) return;
        const char *n = env->GetStringUTFChars(args->nice_name, 0);
        if (n) {
            if (strcmp(n, "com.android.providers.media.module") == 0 ||
                strcmp(n, "com.android.providers.media") == 0) {
                target = true;
            }
            env->ReleaseStringUTFChars(args->nice_name, n);
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!target) return;
        
        LOGI("--- 成功进入 MediaProvider 进程，正在寻找 libbinder.so ---");
        dev_t d; ino_t i;
        if (get_lib_info("libbinder.so", &d, &i)) {
            api->pltHookRegister(d, i, "ioctl", (void *)my_ioctl, (void **)&orig_ioctl);
            if (api->pltHookCommit()) {
                LOGI("+++ ioctl PLT Hook 注入成功！底线监听已开启 +++");
            }
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
