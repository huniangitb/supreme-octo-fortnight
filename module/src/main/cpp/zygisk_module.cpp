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

// ABI 补丁，防止无 C++ 标准库环境引发的链接异常
extern "C" {
    void __cxa_pure_virtual() { while (1); }
}

static int (*orig_ioctl)(int fd, int request, void *arg);

static const char* MON_PATH = "/storage/emulated/0";
static const size_t MON_LEN = 19;

// 补齐 NDK 旧版头文件中可能缺失的 SG (Scatter-Gather) 结构体
// Android 8.0+ 的 Binder 驱动通过增加 buffers_size 字段优化了内存映射
struct my_binder_transaction_data_sg {
    struct binder_transaction_data tr;
    binder_size_t buffers_size;
};

// 动态合成 SG 指令码，彻底告别硬编码！
// 完美兼容 32 位和 64 位的指针大小差异
static const uint32_t CMD_BR_TRANSACTION_SG = _IOR('r', 17, struct my_binder_transaction_data_sg);
static const uint32_t CMD_BR_REPLY_SG = _IOR('r', 18, struct my_binder_transaction_data_sg);

static void scan_parcel(void *buffer, size_t size, uint32_t cmd, uint32_t code) {
    if (!buffer || size < MON_LEN) return;
    unsigned char *ptr = (unsigned char *)buffer;

    for (size_t i = 0; i <= size - MON_LEN; i++) {
        bool is_u8 = (ptr[i] == '/' && memcmp(ptr + i, MON_PATH, MON_LEN) == 0);
        bool is_u16 = (ptr[i] == '/' && ptr[i+1] == 0 && i + MON_LEN*2 <= size);

        if (is_u16) {
            for (size_t j = 0; j < MON_LEN; j++) {
                if (ptr[i + j*2] != MON_PATH[j] || ptr[i + j*2 + 1] != 0) { is_u16 = false; break; }
            }
        }

        if (is_u8 || is_u16) {
            char path[512] = {0};
            size_t p_idx = 0;
            size_t step = is_u8 ? 1 : 2;
            size_t curr = i;
            
            while (curr < size && p_idx < 511) {
                unsigned short c = is_u8 ? ptr[curr] : (ptr[curr] | (ptr[curr+1] << 8));
                if (c == 0 || c < 32 || c > 126) break;
                path[p_idx++] = (char)c;
                curr += step;
            }
            if (p_idx >= MON_LEN) {
                LOGI("[%s|C:%u] 监控命中: %s", 
                    (cmd == BR_TRANSACTION || cmd == CMD_BR_TRANSACTION_SG) ? "REQ" : "REP", 
                    code, path);
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
            uint32_t cmd = *(uint32_t *)p;
            p += 4;

            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
                struct binder_transaction_data *tr = (struct binder_transaction_data *)p;
                if (tr->data_size > 0 && tr->data.ptr.buffer) 
                    scan_parcel((void *)tr->data.ptr.buffer, tr->data_size, cmd, tr->code);
                
                // 基于已知结构体精确步进
                p += sizeof(struct binder_transaction_data);
            } 
            else if (cmd == CMD_BR_TRANSACTION_SG || cmd == CMD_BR_REPLY_SG) {
                struct my_binder_transaction_data_sg *tr_sg = (struct my_binder_transaction_data_sg *)p;
                if (tr_sg->tr.data_size > 0 && tr_sg->tr.data.ptr.buffer)
                    scan_parcel((void *)tr_sg->tr.data.ptr.buffer, tr_sg->tr.data_size, cmd, tr_sg->tr.code);
                
                // 基于已知 SG 结构体精确步进
                p += sizeof(struct my_binder_transaction_data_sg);
            } 
            else {
                // 致命漏洞修补：
                // _IOC_SIZE 解析非数据指令（如 BR_NOOP等）会得出荒谬值，导致指针严重跑飞。
                // 安全起见，一旦遇到非目标指令，直接舍弃剩余缓冲区，打破无限循环与越界崩溃的风险。
                break;
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
        if (n && strcmp(n, "com.android.providers.media.module") == 0) target = true;
        env->ReleaseStringUTFChars(args->nice_name, n);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!target) return;
        dev_t d; ino_t i;
        if (get_lib_info("libbinder.so", &d, &i)) {
            api->pltHookRegister(d, i, "ioctl", (void *)my_ioctl, (void **)&orig_ioctl);
            api->pltHookCommit();
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
