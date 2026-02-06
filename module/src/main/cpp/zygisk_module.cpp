#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/system_properties.h> // 用于 PROP_VALUE_MAX

#include "zygisk.hpp"
#include "dobby.h"

// ============================================================================
// 1. 配置区域：在这里修改你的规则
// ============================================================================

// 定义日志标签
#define LOG_TAG "ZygiskPropDobby"

// 宏定义：打印日志
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 属性处理规则结构体
struct PropRule {
    const char* key;    // 要匹配的属性名
    const char* value;  // 替换后的值。如果为 NULL，则表示"剔除/隐藏"
};

// 【在此处添加或修改你的规则】
static const PropRule CONFIG_RULES[] = {
    // 示例：替换 ro.build.tags 为 release-keys
    { "ro.build.tags", "release-keys" },
    
    // 示例：替换 usb 状态
    { "sys.usb.state", "mtp" },
    
    // 示例：替换厂商名
    { "ro.product.manufacturer", "Google" },

    // 示例：剔除/隐藏某个属性 (设为 NULL)
    // 比如隐藏 zygisk 注入标记或者调试标记
    { "ro.debuggable", "0" },
    { "example.prop.to.hide", NULL } 
};

// 计算规则数量
#define RULE_COUNT (sizeof(CONFIG_RULES) / sizeof(CONFIG_RULES[0]))

// ============================================================================
// 2. 核心 Hook 逻辑 (纯 C 实现)
// ============================================================================

// 定义原始函数指针类型
typedef int (*system_property_get_t)(const char *name, char *value);
static system_property_get_t orig_system_property_get = NULL;

// 我们的替换函数
// Android 属性最大长度通常是 92 (PROP_VALUE_MAX)
int my_system_property_get(const char *name, char *value) {
    // 1. 先调用原始函数获取真实系统值
    int len = orig_system_property_get(name, value);

    // 安全检查
    if (name == NULL || value == NULL) {
        return len;
    }

    // 2. 遍历规则表进行匹配
    for (int i = 0; i < RULE_COUNT; i++) {
        // 使用 strcmp 进行 C 风格字符串比较
        if (strcmp(name, CONFIG_RULES[i].key) == 0) {
            
            // 命中规则！
            const char* target_val = CONFIG_RULES[i].value;

            if (target_val == NULL) {
                // === 策略：剔除/隐藏 ===
                // 将值置空
                value[0] = '\0';
                // 返回 0 表示未找到该属性
                
                LOGI("Hit Rule [HIDE]: prop=[%s] | action=removed", name);
                return 0; 
            } else {
                // === 策略：替换 ===
                // 使用 strncpy 防止缓冲区溢出 (保留1字节给结尾符)
                // PROP_VALUE_MAX 通常为 92，但在 NDK 中可能未定义，安全起见硬编码保护或用标准值
                strncpy(value, target_val, 91);
                value[91] = '\0'; // 确保字符串正常结束
                
                int new_len = strlen(target_val);
                
                LOGI("Hit Rule [REPLACE]: prop=[%s] | orig=[%d] | new=[%s]", name, len, value);
                return new_len;
            }
        }
    }

    // 未命中规则，返回原始结果
    return len;
}

// ============================================================================
// 3. Zygisk 模块接口
// ============================================================================

class PropHookModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // =========================================================
        // 过滤逻辑：只针对用户应用 (UID >= 10000)
        // =========================================================
        // Root = 0, System = 1000, Shell = 2000
        // 普通 APP 从 10000 开始
        
        int app_uid = args->uid;
        if (app_uid < 10000) {
            return; // 系统应用，直接跳过，不注入
        }

        // =========================================================
        // Dobby Hook 执行
        // =========================================================
        
        // 解析 libc.so 中的 __system_property_get 函数地址
        // 这是 Android 读取属性的最底层导出函数 (Android 5.0 - Android 14+ 通用)
        void *func_addr = DobbySymbolResolver(NULL, "__system_property_get");

        if (func_addr != NULL) {
            // 安装 Hook
            // func_addr: 目标地址
            // my_system_property_get: 我们的函数
            // &orig_system_property_get: 存储原始函数的跳板
            int ret = DobbyHook(func_addr, (void *)my_system_property_get, (void **)&orig_system_property_get);
            
            if (ret == 0) {
                // 仅在 Hook 成功时（可选）打印一条调试信息，证明注入成功
                // 生产环境如果觉得这一条日志太多，可以注释掉
               // LOGI("Hook installed success for UID: %d", app_uid);
            } else {
                LOGE("Failed to hook __system_property_get for UID: %d", app_uid);
            }
        } else {
            LOGE("Symbol __system_property_get not found!");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 清理工作（如果需要）
    }

private:
    zygisk::Api *api;
};

// 注册模块
REGISTER_ZYGISK_MODULE(PropHookModule)