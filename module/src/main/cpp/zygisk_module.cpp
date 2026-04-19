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

// ABI 补丁，防止无 C++ 标准库引发链接崩溃
extern "C" {
    void __cxa_pure_virtual() { while (1); }
}

static int (*orig_ioctl)(int fd, int request, void *arg);

static const char* MON_PATH = "/storage/emulated/0";
static const size_t MON_LEN = 19;

// 补齐 SG 结构体
struct my_binder_transaction_data_sg {
    struct binder_transaction_data tr;
    binder_size_t buffers_size;
};

// 动态合成 SG 指令码
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
            // 提取当前指令
            uint32_t cmd = *(uint32_t *)p;
            // 指针向后走 4 字节，跳过指令本身
            p += 4;

            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
                struct binder_transaction_data *tr = (struct binder_transaction_data *)p;
                if (tr->data_size > 0 && tr->data.ptr.buffer) {
                    scan_parcel((void *)tr->data.ptr.buffer, tr->data_size, cmd, tr->code);
                }
                // 精确步过载荷体
                p += sizeof(struct binder_transaction_data);
            } 
            else if (cmd == CMD_BR_TRANSACTION_SG || cmd == CMD_BR_REPLY_SG) {
                struct my_binder_transaction_data_sg *tr_sg = (struct my_binder_transaction_data_sg *)p;
                if (tr_sg->tr.data_size > 0 && tr_sg->tr.data.ptr.buffer) {
                    scan_parcel((void *)tr_sg->tr.data.ptr.buffer, tr_sg->tr.data_size, cmd, tr_sg->tr.code);
                }
                p += sizeof(struct my_binder_transaction_data_sg);
            } 
            else {
                // 正确的非目标指令跳过逻辑：
                // 使用 _IOC_SIZE 提取内核宏定义的有效载荷大小，并保证 4 字节对齐
                // 如果是 BR_NOOP 等无载荷指令，_IOC_SIZE 计算结果为 0，p += 0 是绝对安全的，因为前面的 p+=4 已经保证了循环前进
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
            // 兼容新老 Android 版本的 MediaProvider 进程名
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
            } else {
                LOGI("!!! ioctl PLT Hook 提交失败 !!!");
            }
        } else {
            LOGI("!!! 未能在内存中找到 libbinder.so !!!");
        }
    }
};

REGISTER_ZYGISK_MODULE(MediaMonitor)
