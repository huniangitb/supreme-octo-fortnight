#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "zygisk.hpp"
#include "dobby.h"

// ============================================================================
// 1. 模块配置与日志定义
// ============================================================================

#define LOG_TAG "ZygiskPropMod"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 属性规则结构体
struct PropRule {
    const char* key;    // 目标属性名
    const char* value;  // 替换后的值 (设为 NULL 则表示隐藏该属性)
};

/**
 * 在这里修改你的规则编码
 */
static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Samsung" }, // 示例：修改厂商名
    { "test.hidden.prop", NULL }              // 示例：完全剔除该属性
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. Hook 业务逻辑 (纯 C 库实现)
// ============================================================================

// 定义原始函数指针 (针对 libc 中的 __system_property_get)
typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

// 我们的替换函数
int my_system_property_get(const char *name, char *value) {
    // 1. 调用原始函数
    int len = orig_system_property_get(name, value);

    if (name == NULL || value == NULL) return len;

    // 2. 遍历规则 (使用 C 库函数 strcmp)
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            
            const char* target_val = RULES[i].value;

            if (target_val == NULL) {
                // 命中规则：剔除/隐藏
                value[0] = '\0';
                LOGI("Hit rule [HIDE]: %s", name);
                return 0;
            } else {
                // 命中规则：替换
                // 使用 strncpy 确保安全，Android 属性值通常最大 92 字节
                strncpy(value, target_val, 91);
                value[91] = '\0';
                int new_len = (int)strlen(value);
                
                LOGI("Hit rule [REPLACE]: %s -> %s", name, value);
                return new_len;
            }
        }
    }

    return len;
}

// ============================================================================
// 3. Zygisk 接口实现 (适配 ModuleBase)
// ============================================================================

class MyPropModule : public zygisk::ModuleBase {
public:
    // onLoad 在模块加载时调用
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    // preAppSpecialize 在应用进程 specialize 之前调用（具有 Zygote 权限）
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 核心要求：规避系统应用
        // Android 中 UID < 10000 的通常是系统、电话、Shell 等
        if (args->uid < 10000) {
            return;
        }

        // 执行 Hook
        // 从 libc.so 中寻找 __system_property_get
        void *target_addr = DobbySymbolResolver(NULL, "__system_property_get");
        
        if (target_addr != NULL) {
            int result = DobbyHook(
                target_addr, 
                (dobby_dummy_func_t)my_system_property_get, 
                (dobby_dummy_func_t *)&orig_system_property_get
            );

            if (result == 0) {
                // 成功安装 Hook
                LOGI("Successfully hooked __system_property_get for UID: %d", args->uid);
            }
        } else {
            LOGE("Failed to resolve symbol: __system_property_get");
        }
    }

    // 即使不使用也要根据基类要求声明（头文件中使用了 override）
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {}

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// 注册模块
REGISTER_ZYGISK_MODULE(MyPropModule)