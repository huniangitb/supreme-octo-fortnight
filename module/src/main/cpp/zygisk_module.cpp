#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <sys/system_properties.h> // 需要 prop_info 定义

#include "zygisk.hpp"

// ============================================================================
// 1. 配置规则
// ============================================================================

#define LOG_TAG "ZygiskPropHook"
// 调试时可以开启 Log，生产环境建议关闭以防刷屏
// #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGD(...) 

struct PropRule {
    const char* key;
    const char* value;
};

// 【在此配置你的规则】
static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Google" },
    // 针对特定检测的属性
    { "ro.modversion", NULL } 
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// 辅助函数：查找规则
// 返回 NULL 表示未命中，否则返回目标值(可能为NULL表示剔除)
static const char* find_replacement(const char* name) {
    if (name == NULL) return nullptr;
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            return RULES[i].value;
        }
    }
    return nullptr; // 使用 nullptr 区分"未命中"
}

// ============================================================================
// 2. Hook 逻辑 - PART A: __system_property_get (传统方式)
// ============================================================================

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

int my_system_property_get(const char *name, char *value) {
    int len = 0;
    if (orig_system_property_get) {
        len = orig_system_property_get(name, value);
    }
    
    // 查找是否命中规则（复用查找逻辑）
    // 注意：这里我们重新遍历一次，因为原始值可能并不是我们想要的
    // 如果 name 在规则表中，直接覆盖
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            const char* target_val = RULES[i].value;
            if (target_val == NULL) {
                value[0] = '\0';
                return 0;
            } else {
                strncpy(value, target_val, 91);
                value[91] = '\0';
                return (int)strlen(value);
            }
        }
    }
    return len;
}

// ============================================================================
// 3. Hook 逻辑 - PART B: __system_property_read_callback (现代方式)
// ============================================================================

// 定义回调函数的函数指针类型
typedef void (*prop_callback_func)(void *cookie, const char *name, const char *value, uint32_t serial);

// 定义原始 read_callback 函数类型
typedef void (*system_property_read_callback_t)(const prop_info *pi, prop_callback_func callback, void *cookie);
static system_property_read_callback_t orig_system_property_read_callback = NULL;

// 【关键技术点】: 线程局部存储 (Thread Local Storage)
// 因为 read_callback 是异步回调，我们不能通过参数传递原始的 callback。
// 使用 thread_local 保证多线程并发读取属性时，不会串台。
static thread_local prop_callback_func g_orig_app_callback = nullptr;

// 我们的代理回调：系统读到底层真实值后，会调用这个函数
static void my_prop_proxy_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    // 1. 获取应用原本想要的回调函数
    prop_callback_func app_callback = g_orig_app_callback;
    if (!app_callback) return;

    // 2. 检查是否需要替换
    const char* target_val = NULL;
    bool matched = false;
    
    // 遍历规则
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            target_val = RULES[i].value;
            matched = true;
            break;
        }
    }

    if (matched) {
        if (target_val == NULL) {
            // 策略：隐藏。传空字符串或者直接拦截不回调？
            // 通常传空字符串比较安全，直接不回调可能导致 App 逻辑卡死
            app_callback(cookie, name, "", serial);
            LOGD("read_callback: HIDDEN %s", name);
        } else {
            // 策略：替换
            app_callback(cookie, name, target_val, serial);
            LOGD("read_callback: REPLACED %s -> %s", name, target_val);
        }
    } else {
        // 未命中，透传原始值
        app_callback(cookie, name, value, serial);
    }
}

// 我们的 Hook 入口
void my_system_property_read_callback(const prop_info *pi, prop_callback_func callback, void *cookie) {
    if (orig_system_property_read_callback) {
        // 1. 保存 App 原始的回调函数到 TLS
        g_orig_app_callback = callback;
        
        // 2. 调用原始系统函数，但把回调替换成我们的代理函数 (my_prop_proxy_callback)
        orig_system_property_read_callback(pi, my_prop_proxy_callback, cookie);
    }
}


// ============================================================================
// 4. Zygisk 模块主体
// ============================================================================

class PropModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 1. 过滤系统应用 (UID < 10000)
        if (args->uid < 10000) return;

        // 2. 执行 PLT Hook
        hookAllLoadedModules();
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override { }

private:
    zygisk::Api *api;
    JNIEnv *env;

    void hookAllLoadedModules() {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp == NULL) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            uintptr_t start, end;
            char perms[5];
            uint64_t offset;
            uint32_t dev_major, dev_minor;
            unsigned long inode;
            char path[256];

            int fields = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64 " %x:%x %lu %s",
                                &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);

            if (fields == 8 && strstr(perms, "x") && inode != 0) {
                // 排除 libc.so 自身 (防止递归) 和 模块自身
                if (strstr(path, "libc.so") == NULL && strstr(path, "zygisk") == NULL) {
                    
                    dev_t dev = makedev(dev_major, dev_minor);

                    // Hook 1: 传统的 get (Android 7 及以下为主，部分老代码)
                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);

                    // Hook 2: 现代的 read_callback (Android 8+ / API 26+)
                    // 这是大多数通过 C++ (libbase) 或 Java (SystemProperties) 访问属性的底层入口
                    api->pltHookRegister(dev, inode, "__system_property_read_callback", 
                                        (void *)my_system_property_read_callback, 
                                        (void **)&orig_system_property_read_callback);
                }
            }
        }
        fclose(fp);

        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(PropModule)