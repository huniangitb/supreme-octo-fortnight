#include <android/log.h>
#include <string.h>
#include <jni.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>      // 包含这个以确保 SCNxPTR 等定义，虽然我们改用了 %lx
#include <sys/system_properties.h>

#include "zygisk.hpp"

// ============================================================================
// 1. 规则配置
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

static const char* find_replacement(const char* name) {
    if (!name) return nullptr;
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(name, RULES[i].key) == 0) return RULES[i].value;
    }
    return nullptr;
}

// ============================================================================
// 2. Native Hook 逻辑 (处理 Serial 绕过缓存)
// ============================================================================

typedef uint32_t (*system_property_serial_t)(const prop_info *);
static system_property_serial_t orig_system_property_serial = nullptr;

typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = nullptr;

// 序列号拦截：强制让缓存失效
uint32_t my_system_property_serial(const prop_info *pi) {
    if (pi && orig_system_property_read) {
        char name[PROP_NAME_MAX];
        char value[PROP_VALUE_MAX];
        // 探测当前的 pi 对应哪个属性
        orig_system_property_read(pi, name, value);
        if (find_replacement(name)) {
            // 返回一个不断变化的随机值，欺骗客户端缓存已过期
            return (uint32_t)(rand() % 2000 + 5000);
        }
    }
    return orig_system_property_serial ? orig_system_property_serial(pi) : 0;
}

// 读取拦截
int my_system_property_read(const prop_info *pi, char *name, char *value) {
    int len = 0;
    if (orig_system_property_read) len = orig_system_property_read(pi, name, value);
    
    const char* replace = find_replacement(name);
    if (replace) {
        if (replace[0] == '\0') { 
            if (value) value[0] = '\0'; 
            return 0; 
        }
        strncpy(value, replace, 91);
        value[91] = '\0';
        return (int)strlen(value);
    }
    return len;
}

// ============================================================================
// 3. JNI Hook 逻辑 (绕过 Java 层 PropertyCache)
// ============================================================================

static jstring (*orig_native_get)(JNIEnv*, jclass, jstring, jstring) = nullptr;

jstring my_native_get(JNIEnv* env, jclass clazz, jstring key_j, jstring def_j) {
    if (!key_j) return orig_native_get(env, clazz, key_j, def_j);

    const char* key = env->GetStringUTFChars(key_j, nullptr);
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

        // 1. JNI Hook (精准打击 Java 层)
        JNINativeMethod methods[] = {
            { "native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)my_native_get }
        };
        api->hookJniNativeMethods(env, "android/os/SystemProperties", methods, 1);
        if (methods[0].fnPtr) {
            *(void **)&orig_native_get = methods[0].fnPtr;
        }

        // 2. PLT Hook (精准打击 Native 层)
        hookLib("libandroid_runtime.so");
        hookLib("libbase.so");
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

            // 修复点：改用 %lx 以避免 SCNxPTR 宏在某些环境下的编译问题
            int fields = sscanf(line, "%lx-%lx %4s %*s %x:%x %lu %s", 
                               &start, &end, perms, &maj, &min, &inode, path);

            if (fields == 7 && strstr(perms, "x") && strstr(path, libname)) {
                dev_t dev = makedev(maj, min);
                
                // 拦截序列号检查
                api->pltHookRegister(dev, inode, "__system_property_serial", 
                                    (void *)my_system_property_serial, 
                                    (void **)&orig_system_property_serial);

                // 拦截读取
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