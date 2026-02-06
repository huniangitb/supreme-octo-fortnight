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

// 递归保护锁：确保在 Hook 内部调用 Log 或其他系统函数时不会无限循环
static thread_local bool g_is_hooking = false;

struct PropRule {
    const char* key;
    const char* value;
};

// 【在此处定义你的规则】
static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Google" },
    { "ro.modversion", nullptr } // nullptr 表示剔除/隐藏
};
#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 原始函数指针定义
// ============================================================================

typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = nullptr;

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = nullptr;

// ============================================================================
// 3. Hook 逻辑实现 (纯 C 函数)
// ============================================================================

int my_system_property_read(const prop_info *pi, char *name, char *value) {
    if (g_is_hooking) return orig_system_property_read(pi, name, value);
    g_is_hooking = true;

    int len = orig_system_property_read(pi, name, value);
    
    if (len >= 0 && name) {
        for (int i = 0; i < RULE_COUNT; i++) {
            if (strcmp(name, RULES[i].key) == 0) {
                const char* replace = RULES[i].value;
                if (replace == nullptr) {
                    value[0] = '\0';
                    len = 0;
                } else {
                    strncpy(value, replace, PROP_VALUE_MAX - 1);
                    value[PROP_VALUE_MAX - 1] = '\0';
                    len = (int)strlen(value);
                }
                break;
            }
        }
    }

    g_is_hooking = false;
    return len;
}

int my_system_property_get(const char *name, char *value) {
    if (g_is_hooking) return orig_system_property_get(name, value);
    g_is_hooking = true;

    int len = orig_system_property_get(name, value);

    if (len >= 0 && name && value) {
        for (int i = 0; i < RULE_COUNT; i++) {
            if (strcmp(name, RULES[i].key) == 0) {
                const char* replace = RULES[i].value;
                if (replace == nullptr) {
                    value[0] = '\0';
                    len = 0;
                } else {
                    strncpy(value, replace, PROP_VALUE_MAX - 1);
                    value[PROP_VALUE_MAX - 1] = '\0';
                    len = (int)strlen(value);
                }
                break;
            }
        }
    }

    g_is_hooking = false;
    return len;
}

// ============================================================================
// 4. Zygisk 模块类
// ============================================================================

class PropModModule : public zygisk::ModuleBase {
public:
    // 必须要实现这些虚函数
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 核心要求 1：规避系统应用 (UID < 10000)
        if (args->uid < 10000) return;

        // 核心要求 2：隐藏路径，尝试在命名空间中卸载模块挂载点
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

#ifdef USE_DOBBY
        // 执行 Dobby Hook
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

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 不需要处理
    }

private:
    // 修复点：在这里声明成员变量
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

// 注册模块
REGISTER_ZYGISK_MODULE(PropModModule)