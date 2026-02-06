#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <sys/system_properties.h>

#include "zygisk.hpp"

// ============================================================================
// 1. 规则配置
// ============================================================================

#define LOG_TAG "ZygiskPropCore"
// 调试开关：生产环境请注释掉 LOGD
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
//#define LOGD(...) 

struct PropRule {
    const char* key;
    const char* value;
};

// 【在此配置你的规则】
static const PropRule RULES[] = {
    // 基础指纹模拟
    { "ro.build.tags", "release-keys" },
    { "ro.build.type", "user" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "ro.adb.secure", "1" },
    { "sys.usb.state", "mtp" },
    
    // 厂商伪装
    { "ro.product.manufacturer", "Xiaomi" },
    { "ro.product.brand", "Xiaomi" },
    { "ro.product.model", "Mi 11" },
    
    // 针对特定检测的隐藏
    { "ro.modversion", NULL },
    { "ro.magisk.deny.mount", NULL }
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 核心逻辑: 通用替换处理
// ============================================================================

// 统一的处理逻辑：检查 name，如果在规则中，则修改 value
// 返回值：新的 value 长度；如果未修改则返回 -1
static int try_replace_prop(const char *name, char *value) {
    if (name == NULL || value == NULL) return -1;

    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            const char* target_val = RULES[i].value;
            
            if (target_val == NULL) {
                // 策略：隐藏 (置空)
                value[0] = '\0';
                LOGD("Hiding prop: %s", name);
                return 0;
            } else {
                // 策略：替换
                // PROP_VALUE_MAX = 92, 安全起见用 91
                strncpy(value, target_val, 91);
                value[91] = '\0';
                LOGD("Replacing prop: %s -> %s", name, target_val);
                return (int)strlen(value);
            }
        }
    }
    return -1; // 未命中
}

// ============================================================================
// 3. Hook 函数定义 (覆盖 Android 12+ 三种读取路径)
// ============================================================================

// ----------------------------------------------------------------------------
// Hook 1: __system_property_get
// 最传统的 API，部分老应用和 Shell 命令使用
// ----------------------------------------------------------------------------
typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

int my_system_property_get(const char *name, char *value) {
    int len = 0;
    if (orig_system_property_get) {
        len = orig_system_property_get(name, value);
    }
    
    int new_len = try_replace_prop(name, value);
    if (new_len != -1) {
        return new_len;
    }
    return len;
}

// ----------------------------------------------------------------------------
// Hook 2: __system_property_read
// 【关键】Android 12+ Java 层 SystemProperties.get() 底层常走此路
// 签名: int __system_property_read(const prop_info *pi, char *name, char *value);
// ----------------------------------------------------------------------------
typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = NULL;

int my_system_property_read(const prop_info *pi, char *name, char *value) {
    int len = 0;
    if (orig_system_property_read) {
        // 先调用原始函数，系统会把 name 和 value 填好
        len = orig_system_property_read(pi, name, value);
    }

    // 系统填好后，我们再根据 name 篡改 value
    int new_len = try_replace_prop(name, value);
    if (new_len != -1) {
        return new_len;
    }
    return len;
}

// ----------------------------------------------------------------------------
// Hook 3: __system_property_read_callback
// 现代 C++ 库 (android::base::GetProperty) 使用
// ----------------------------------------------------------------------------
typedef void (*prop_callback_func)(void *cookie, const char *name, const char *value, uint32_t serial);
typedef void (*system_property_read_callback_t)(const prop_info *pi, prop_callback_func callback, void *cookie);

static system_property_read_callback_t orig_system_property_read_callback = NULL;
static thread_local prop_callback_func g_orig_app_callback = nullptr;

// 代理回调
static void my_prop_proxy_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    prop_callback_func app_callback = g_orig_app_callback;
    if (!app_callback) return;

    // 检查是否命中规则
    const char* target_val = NULL;
    bool matched = false;
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            target_val = RULES[i].value;
            matched = true;
            break;
        }
    }

    if (matched) {
        if (target_val == NULL) {
            app_callback(cookie, name, "", serial); // 隐藏
        } else {
            app_callback(cookie, name, target_val, serial); // 替换
        }
    } else {
        app_callback(cookie, name, value, serial); // 透传
    }
}

void my_system_property_read_callback(const prop_info *pi, prop_callback_func callback, void *cookie) {
    if (orig_system_property_read_callback) {
        g_orig_app_callback = callback;
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
        // 绝对不要开启 DLCLOSE，否则安全库延迟调用时必崩
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) return;
        hookAllLoadedModules();
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override { }

private:
    zygisk::Api *api;
    JNIEnv *env;

    // 检查路径是否在黑名单中
    bool is_ignored_lib(const char* path) {
        // 【关键黑名单】
        // 这些库绝对不能 Hook，否则会崩溃或死锁
        static const char* IGNORE_LIST[] = {
            "libc.so",              // 自身
            "zygisk",               // 模块自身
            "libnativebridge.so",   // 系统桥接库 (崩溃日志中出现)
            "libdl.so",             // 动态链接器
            "libm.so",              // 数学库
            "liblog.so",            // 日志库
            
            // 【风控/反作弊库】(根据崩溃日志添加)
            "libmetasec_ml.so",     // 字节系风控
            "libmsao.so",           // 另一常见的风控
            "libixia.so",           // 阿里系/加固
            "libjiagu.so",          // 360加固
            "libnesec.so",          // 网易易盾
            "libunwind.so"          // 栈回溯库
        };

        for (const char* item : IGNORE_LIST) {
            if (strstr(path, item) != NULL) {
                return true; // 在黑名单里，跳过
            }
        }
        return false;
    }

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
                
                // 【核心修改】增加黑名单过滤
                if (!is_ignored_lib(path)) {
                    
                    dev_t dev = makedev(dev_major, dev_minor);

                    // 注册三个核心 Hook
                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);

                    api->pltHookRegister(dev, inode, "__system_property_read", 
                                        (void *)my_system_property_read, 
                                        (void **)&orig_system_property_read);

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