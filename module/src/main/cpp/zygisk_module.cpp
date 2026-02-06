#include <android/log.h>
#include <string.h>
#include <jni.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>

#include "zygisk.hpp"

#define LOG_TAG "ZygiskStealth"
// 生产环境建议关闭日志以保持隐蔽
#define LOGD(...) 

// ============================================================================
// 1. 规则与缓存配置
// ============================================================================

struct PropRule { const char* key; const char* value; };

static const PropRule RULES[] = {
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    { "ro.product.manufacturer", "Google" },
    { "ro.product.model", "Pixel 7" },
    { "ro.modversion", NULL } 
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// 查找匹配规则
static const char* find_replacement(const char* name) {
    if (!name) return NULL;
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) return RULES[i].value;
    }
    return NULL;
}

// ============================================================================
// 2. Native Hook 逻辑 (处理 Serial 和 Read)
// ============================================================================

typedef uint32_t (*system_property_serial_t)(const prop_info *);
static system_property_serial_t orig_system_property_serial = NULL;

typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = NULL;

// 【关键】Hook 序列号检查
// 当应用询问“这个属性变了吗？”
uint32_t my_system_property_serial(const prop_info *pi) {
    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    
    // 我们需要知道这个 pi 对应的是哪个属性
    if (orig_system_property_read && pi) {
        orig_system_property_read(pi, name, value);
        if (find_replacement(name)) {
            // 如果是我们目标拦截的属性，返回一个随机的大序列号
            // 这会强制应用认为缓存已过期，从而触发 my_system_property_read
            return (uint32_t)(rand() % 1000 + 10000); 
        }
    }
    return orig_system_property_serial ? orig_system_property_serial(pi) : 0;
}

// Hook 读取函数
int my_system_property_read(const prop_info *pi, char *name, char *value) {
    int len = 0;
    if (orig_system_property_read) len = orig_system_property_read(pi, name, value);
    
    const char* replace = find_replacement(name);
    if (replace) {
        if (replace[0] == '\0') { value[0] = '\0'; return 0; }
        strncpy(value, replace, 91);
        value[91] = '\0';
        return (int)strlen(value);
    }
    return len;
}

// ============================================================================
// 3. JNI Hook 逻辑 (绕过 Java 层缓存)
// ============================================================================

static jstring (*orig_native_get)(JNIEnv*, jclass, jstring, jstring) = NULL;

jstring my_native_get(JNIEnv* env, jclass clazz, jstring key_j, jstring def_j) {
    if (!key_j) return orig_native_get(env, clazz, key_j, def_j);

    const char* key = env->GetStringUTFChars(key_j, NULL);
    const char* replace = find_replacement(key);
    env->ReleaseStringUTFChars(key_j, key);

    if (replace) {
        if (replace[0] == '\0') return env->NewStringUTF("");
        return env->NewStringUTF(replace);
    }
    return orig_native_get(env, clazz, key_j, def_j);
}

// ============================================================================
// 4. Zygisk 模块实现
// ============================================================================

class StealthModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) return;

        // A. JNI Hook: 它是最直接绕过 Java 层 PropertyCache 的手段
        JNINativeMethod methods[] = {
            { "native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)my_native_get }
        };
        api->hookJniNativeMethods(env, "android/os/SystemProperties", methods, 1);
        *(void **)&orig_native_get = methods[0].fnPtr;

        // B. 精准 PLT Hook: 覆盖 Native 读取和 序列号检查
        hookLib("libandroid_runtime.so");
        hookLib("libbase.so"); // 很多现代 App 里的 Native 检测喜欢用 libbase
    }

private:
    zygisk::Api *api;
    JNIEnv *env;

    void hookLib(const char* libname) {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            uintptr_t start, end;
            char perms[5];
            uint32_t maj, min;
            unsigned long inode;
            char path[256];
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %*s %x:%x %lu %s", 
                       &start, &end, perms, &maj, &min, &inode, path) != 7) continue;

            if (strstr(perms, "x") && strstr(path, libname)) {
                dev_t dev = makedev(maj, min);
                
                // Hook 关键：Serial (绕过缓存的关键)
                api->pltHookRegister(dev, inode, "__system_property_serial", 
                                    (void *)my_system_property_serial, 
                                    (void **)&orig_system_property_serial);

                // Hook 关键：Read
                api->pltHookRegister(dev, inode, "__system_property_read", 
                                    (void *)my_system_property_read, 
                                    (void **)&orig_system_property_read);
            }
        }
        fclose(fp);
        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(StealthModule)