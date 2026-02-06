#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h> // 【关键】解决 makedev 未定义报错
#include <inttypes.h>      // 用于 SCNxPTR 格式化打印

#include "zygisk.hpp"

// ============================================================================
// 1. 配置区域：规则定义
// ============================================================================

#define LOG_TAG "ZygiskPropHook"
// 仅在 Debug 模式打印日志，或者你可以保留 LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct PropRule {
    const char* key;    // 目标属性名
    const char* value;  // 目标值 (NULL 代表隐藏/剔除)
};

// 【在此处修改你的规则】
static const PropRule RULES[] = {
    // 隐藏 Root/Debug 痕迹
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "ro.adb.secure", "1" },
    
    // 模拟设备信息 (示例)
    { "ro.product.manufacturer", "Xiaomi" },
    { "ro.product.model", "Mi 11" },

    // 剔除特定的 Hook 检测属性
    { "ro.modversion", NULL },
    { "example.detect.prop", NULL }
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 业务逻辑 (纯 C 实现)
// ============================================================================

// 原始函数指针
typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

// 我们的代理函数
int my_system_property_get(const char *name, char *value) {
    int len = 0;
    
    // 1. 先尝试调用原始函数获取真实值
    if (orig_system_property_get) {
        len = orig_system_property_get(name, value);
    }
    
    // 安全检查
    if (name == NULL || value == NULL) return len;

    // 2. 遍历规则表
    for (size_t i = 0; i < RULE_COUNT; i++) {
        // 使用 strcmp 比较 (纯 C 库)
        if (strcmp(name, RULES[i].key) == 0) {
            const char* target_val = RULES[i].value;
            
            if (target_val == NULL) {
                // 策略：隐藏 (模拟属性不存在)
                value[0] = '\0';
                // LOGI("[HIDE] %s", name);
                return 0; 
            } else {
                // 策略：替换
                // 91 是为了防止缓冲区溢出 (PROP_VALUE_MAX 通常为 92)
                strncpy(value, target_val, 91);
                value[91] = '\0';
                // LOGI("[REPLACE] %s -> %s", name, value);
                return (int)strlen(value);
            }
        }
    }

    return len;
}

// ============================================================================
// 3. Zygisk 模块主体 (PLT Hook + 隐身)
// ============================================================================

class PropModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        
        // 【关键隐身】: 告诉 Zygisk 在 Hook 完成后，把本模块从内存映射中移除
        // 这样检测应用扫描 /proc/self/maps 时找不到此模块
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 1. 规避系统应用 (UID < 10000)
        if (args->uid < 10000) {
            return;
        }

        // 2. 注册 PLT Hook
        // 这一步会遍历内存映射，Hook 所有加载的库对 __system_property_get 的引用
        hookAllLoadedModules();
    }
    
    // PLT Hook 需要尽早注册，postAppSpecialize 通常不需要操作
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override { }

private:
    zygisk::Api *api;
    JNIEnv *env;

    // 解析 /proc/self/maps 并批量注册 Hook
    void hookAllLoadedModules() {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp == NULL) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            // 解析 maps 文件的每一行
            // 格式示例: 7f89a00000-7f89a01000 r-xp 00000000 fd:00 12345  /system/lib64/libutils.so
            
            uintptr_t start, end;
            char perms[5];
            uint64_t offset;
            uint32_t dev_major, dev_minor;
            unsigned long inode;
            char path[256];

            int fields = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64 " %x:%x %lu %s",
                                &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);

            // 筛选条件：
            // 1. r-xp: 可读可执行 (代码段)
            // 2. inode != 0: 必须是文件映射
            if (fields == 8 && strstr(perms, "x") && inode != 0) {
                
                // 排除 libc.so 自身 (防止递归调用或死锁)
                // 以及排除我们自己的模块 (虽然我们会自我卸载，但排除一下更安全)
                if (strstr(path, "libc.so") == NULL && strstr(path, "zygisk") == NULL) {
                    
                    // 生成设备 ID
                    dev_t dev = makedev(dev_major, dev_minor);

                    // 向 Zygisk 注册 PLT Hook
                    // 含义：当这个库(dev/inode)调用 "__system_property_get" 时，拦截它
                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);
                }
            }
        }
        fclose(fp);

        // 提交所有注册的 Hook
        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(PropModule)