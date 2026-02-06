#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/system_properties.h>

#include "zygisk.hpp"
#include "dobby.h"

// ============================================================================
// 1. 配置与递归锁
// ============================================================================

#define LOG_TAG "ZygiskPropMod"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// 递归保护锁：线程局部变量，确保不同线程之间互不干扰
static thread_local bool g_is_hooking = false;

struct PropRule {
    const char* key;
    const char* value;
};

static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Google" }
};
#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 原始函数指针
// ============================================================================

typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = nullptr;

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = nullptr;

// ============================================================================
// 3. 安全的拦截函数
// ============================================================================

int my_system_property_read(const prop_info *pi, char *name, char *value) {
    // 1. 递归检查
    if (g_is_hooking) return orig_system_property_read(pi, name, value);

    // 2. 上锁
    g_is_hooking = true;

    int len = orig_system_property_read(pi, name, value);
    
    if (len >= 0) {
        for (int i = 0; i < RULE_COUNT; i++) {
            if (name && strcmp(name, RULES[i].key) == 0) {
                const char* replace = RULES[i].value;
                if (replace) {
                    strncpy(value, replace, PROP_VALUE_MAX - 1);
                    value[PROP_VALUE_MAX - 1] = '\0';
                    len = strlen(value);
                    // 只有在上锁期间调用 LOGD 才是安全的（因为 LOGD 会触发下一层 my_system_property_get，
                    // 但由于 g_is_hooking 已为 true，下一层会直接走 orig）
                    LOGD("Modified read: %s -> %s", name, value);
                }
                break;
            }
        }
    }

    // 3. 解锁
    g_is_hooking = false;
    return len;
}

int my_system_property_get(const char *name, char *value) {
    // 1. 递归检查
    if (g_is_hooking) return orig_system_property_get(name, value);

    // 2. 上锁
    g_is_hooking = true;

    int len = orig_system_property_get(name, value);

    if (name && value) {
        for (int i = 0; i < RULE_COUNT; i++) {
            if (strcmp(name, RULES[i].key) == 0) {
                const char* replace = RULES[i].value;
                if (replace) {
                    strncpy(value, replace, PROP_VALUE_MAX - 1);
                    value[PROP_VALUE_MAX - 1] = '\0';
                    len = strlen(value);
                    LOGD("Modified get: %s -> %s", name, value);
                }
                break;
            }
        }
    }

    // 3. 解锁
    g_is_hooking = false;
    return len;
}

// ============================================================================
// 4. Zygisk 注册
// ============================================================================

class PropModModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) return;

        // 核心隐蔽性操作：尝试在 DenyList 中卸载模块
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

#ifdef USE_DOBBY
        // 使用 Dobby 直接 Hook libc 的导出函数
        void* read_addr = DobbySymbolResolver(nullptr, "__system_property_read");
        if (read_addr) {
            DobbyHook(read_addr, (void*)my_system_property_read, (void**)&orig_system_property_read);
        }

        void* get_addr = DobbySymbolResolver(nullptr, "__system_property_get");
        if (get_addr) {
            DobbyHook(get_addr, (void*)my_system_property_get, (void**)&orig_system_property_get);
        }
#endif
    }
};

REGISTER_ZYGISK_MODULE(PropModModule)