#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h> 
#include <inttypes.h>

#include "zygisk.hpp"

// ============================================================================
// 1. 规则配置
// ============================================================================

struct PropRule {
    const char* key;
    const char* value;
};

// 在这里定义你的规则
static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Xiaomdjji" }, // 可选
    // { "ro.modversion", NULL } // 可选：隐藏
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 业务逻辑 (纯 C，无 Log，高性能)
// ============================================================================

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

int my_system_property_get(const char *name, char *value) {
    int len = 0;
    
    // 1. 调用原始函数 (安全检查)
    if (orig_system_property_get) {
        len = orig_system_property_get(name, value);
    } else {
        // 理论上不应发生，如果发生则直接返回0
        return 0;
    }
    
    // 2. 参数检查
    if (name == NULL || value == NULL) return len;

    // 3. 遍历规则 (移除所有 Log 防止死锁)
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) {
            const char* target_val = RULES[i].value;
            
            if (target_val == NULL) {
                // 隐藏
                value[0] = '\0';
                return 0; 
            } else {
                // 替换 (硬编码91字节保护)
                strncpy(value, target_val, 91);
                value[91] = '\0';
                return (int)strlen(value);
            }
        }
    }

    return len;
}

// ============================================================================
// 3. Zygisk 模块主体
// ============================================================================

class PropModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        
        // 【关键修复】
        // 绝对不要在这里调用 DLCLOSE_MODULE_LIBRARY
        // 因为 PLT Hook 跳转的目标是我们模块内的代码，模块卸载了就会崩溃！
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 1. 严格过滤：绝对不碰系统进程
        // UID < 10000 是系统核心进程，Hook 它们风险极高且容易卡死启动
        if (args->uid < 10000) {
            return;
        }

        // 2. 执行 Hook
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

            // 筛选：可执行段 + 文件映射
            if (fields == 8 && strstr(perms, "x") && inode != 0) {
                
                // 关键过滤：
                // 1. 不 Hook libc.so 自身 (防止递归)
                // 2. 不 Hook 模块自身 (虽然逻辑上可以，但没必要)
                // 3. 仅 Hook 系统库或常用库 (这里采用宽泛策略，Hook 所有非 libc 的库)
                if (strstr(path, "libc.so") == NULL && strstr(path, "zygisk") == NULL) {
                    
                    dev_t dev = makedev(dev_major, dev_minor);

                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);
                }
            }
        }
        fclose(fp);

        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(PropModule)