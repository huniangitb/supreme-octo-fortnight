#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h> // for SCNx64
#include <sys/sysmacros.h>
#include "zygisk.hpp"

// ============================================================================
// 1. 配置区域
// ============================================================================

#define LOG_TAG "ZygiskPropHidden"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 属性规则
struct PropRule {
    const char* key;
    const char* value;
};

static const PropRule RULES[] = {
    // 示例：规避检测
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Xiaomiyh" }, // 示例修改厂商
    // 某些检测应用会查这个
    { "ro.modversion", NULL } 
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// ============================================================================
// 2. 业务逻辑 (保持不变)
// ============================================================================

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

int my_system_property_get(const char *name, char *value) {
    // 必须检查原始函数指针是否存在
    // 如果是 PLT Hook，orig 指针可能在第一次调用时才被填充，
    // 但 Zygisk 的实现通常会在 Register 时填充。
    int len = 0;
    if (orig_system_property_get) {
        len = orig_system_property_get(name, value);
    } else {
        // 极少情况下的回退逻辑，通常不会发生
        return 0;
    }

    if (name == NULL || value == NULL) return len;

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
// 3. Zygisk 模块 (使用 PLT Hook)
// ============================================================================

class PropHiddenModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        
        // 【关键策略 1】: 隐藏模块自身
        // 模块代码执行完毕后，从内存映射中移除模块的 .so 记录
        // 这样检测应用扫描 /proc/self/maps 时就看不到你的模块了
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 过滤系统应用
        if (args->uid < 10000) return;

        LOGI("App UID: %d, Preparing PLT hooks...", args->uid);

        // 【关键策略 2】: 使用 PLT Hook 代替 Inline Hook
        // 我们需要遍历当前加载的所有动态库，Hook 它们对 __system_property_get 的引用
        hookAllModules();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // PLT Hook 需要在 specialize 之后再次确保生效（针对部分动态加载的情况）
        // 但通常 preAppSpecialize 足够覆盖启动时的检测
    }

private:
    zygisk::Api *api;
    JNIEnv *env;

    // 解析 /proc/self/maps 并注册 PLT Hook
    void hookAllModules() {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp == NULL) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            // map line format: 
            // 7f89a00000-7f89a01000 r-xp 00000000 fd:00 12345  /system/lib64/libutils.so
            
            uintptr_t start, end;
            char perms[5];
            uint64_t offset;
            uint32_t dev_major, dev_minor;
            unsigned long inode;
            char path[256];

            // 使用 sscanf 解析关键字段：dev(设备号) 和 inode(节点号) 是 Zygisk 识别文件的关键
            // 注意：%s 读取 path 可能会因为空格截断，但系统库通常无空格
            int fields = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64 " %x:%x %lu %s",
                                &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);

            // 1. 必须是可执行段 (r-xp)
            if (strstr(perms, "x")) {
                // 2. 排除 [anon] 内存段，必须关联到文件
                if (fields == 8 && inode != 0) {
                    // 构建 dev_t
                    dev_t dev = makedev(dev_major, dev_minor);

                    // 3. 注册 Hook
                    // 注意：不要 Hook libc.so 自己调用自己（虽然 PLT 也可以），主要是 Hook 其他库
                    // 如果路径包含 libc.so，通常跳过，防止递归死锁或异常
                    if (strstr(path, "libc.so") == NULL) {
                         api->pltHookRegister(dev, inode, "__system_property_get", 
                                             (void *)my_system_property_get, 
                                             (void **)&orig_system_property_get);
                    }
                }
            }
        }
        fclose(fp);

        // 提交所有 Hook
        if (api->pltHookCommit()) {
            LOGI("PLT Hooks committed successfully.");
        } else {
            LOGE("PLT Hooks commit failed.");
        }
    }
};

REGISTER_ZYGISK_MODULE(PropHiddenModule)