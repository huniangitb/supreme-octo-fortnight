#include <android/log.h>
#include <string.h>
#include <jni.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <sys/system_properties.h>

#include "zygisk.hpp"

#define LOG_TAG "ZygiskFinal"
// 调试开关
// #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGD(...)

// ============================================================================
// 1. 规则定义
// ============================================================================
struct PropRule { const char* key; const char* value; };

static const PropRule RULES[] = {
    // 基础防检测
    { "ro.build.tags", "release-keys" },
    { "ro.debuggable", "0" },
    { "ro.secure", "1" },
    { "sys.usb.state", "mtp" },
    
    // 模拟机型信息 (JuiceSSH 等应用读取这里)
    { "ro.product.manufacturer", "Google" },
    { "ro.product.brand", "Google" },
    { "ro.product.model", "Pixel 6" },
    { "ro.product.device", "oriole" },
    
    // 隐藏特征
    { "ro.modversion", NULL }
};

#define RULE_COUNT (sizeof(RULES) / sizeof(RULES[0]))

// 辅助查找
const char* get_replacement(const char* key) {
    if (!key) return nullptr;
    for (size_t i = 0; i < RULE_COUNT; i++) {
        if (strcmp(key, RULES[i].key) == 0) {
            return RULES[i].value;
        }
    }
    return nullptr;
}

// ============================================================================
// 2. JNI Hook (针对 Java 层 SystemProperties) - 稳如老狗
// ============================================================================

// 原始 JNI 函数
static jstring (*orig_native_get)(JNIEnv*, jclass, jstring, jstring) = nullptr;

// 我们的 JNI 代理
jstring my_native_get(JNIEnv* env, jclass clazz, jstring key_jstr, jstring def_jstr) {
    if (key_jstr == nullptr) return orig_native_get(env, clazz, key_jstr, def_jstr);

    const char* key = env->GetStringUTFChars(key_jstr, nullptr);
    const char* replace_val = get_replacement(key);
    env->ReleaseStringUTFChars(key_jstr, key);

    if (replace_val) {
        LOGD("JNI Hook hit: %s -> %s", key, replace_val);
        // 如果是 NULL (剔除)，返回空字符串
        if (replace_val[0] == '\0') return env->NewStringUTF("");
        return env->NewStringUTF(replace_val);
    }

    return orig_native_get(env, clazz, key_jstr, def_jstr);
}

// ============================================================================
// 3. Native PLT Hook (只针对 libandroid_runtime.so)
// ============================================================================

typedef int (*system_property_read_t)(const prop_info *, char *, char *);
static system_property_read_t orig_system_property_read = NULL;

typedef int (*system_property_get_t)(const char *, char *);
static system_property_get_t orig_system_property_get = NULL;

// 处理 read
int my_system_property_read(const prop_info *pi, char *name, char *value) {
    int len = 0;
    if (orig_system_property_read) len = orig_system_property_read(pi, name, value);
    
    const char* replace = get_replacement(name);
    if (replace) {
        if (replace[0] == '\0') { value[0] = '\0'; return 0; }
        strncpy(value, replace, 91);
        value[91] = '\0';
        return strlen(value);
    }
    return len;
}

// 处理 get
int my_system_property_get(const char *name, char *value) {
    int len = 0;
    if (orig_system_property_get) len = orig_system_property_get(name, value);
    
    const char* replace = get_replacement(name);
    if (replace) {
        if (replace[0] == '\0') { value[0] = '\0'; return 0; }
        strncpy(value, replace, 91);
        value[91] = '\0';
        return strlen(value);
    }
    return len;
}

// ============================================================================
// 4. Zygisk 模块主体
// ============================================================================

class FinalModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 1. 过滤 UID，保护系统进程
        if (args->uid < 10000) return;

        // ---------------------------------------------------------
        // 策略 A: JNI Hook (解决 Java 层读取，如 JuiceSSH)
        // ---------------------------------------------------------
        JNINativeMethod methods[] = {
            { "native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)my_native_get }
        };
        
        api->hookJniNativeMethods(env, "android/os/SystemProperties", methods, 1);
        if (methods[0].fnPtr) {
            *(void **)&orig_native_get = methods[0].fnPtr;
            LOGD("JNI Hook installed");
        }

        // ---------------------------------------------------------
        // 策略 B: 精准 PLT Hook (解决底层库读取)
        // 只 Hook "libandroid_runtime.so"，它是连接 Java 和 Native 的桥梁
        // ---------------------------------------------------------
        hookSpecificLib("libandroid_runtime.so");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {}

private:
    zygisk::Api *api;
    JNIEnv *env;

    // 只 Hook 指定名称的库，极大提高稳定性！
    void hookSpecificLib(const char* target_lib_name) {
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
                // 核心逻辑：只匹配目标库名
                if (strstr(path, target_lib_name) != NULL) {
                    
                    dev_t dev = makedev(dev_major, dev_minor);
                    
                    // Hook read (Android 12+)
                    api->pltHookRegister(dev, inode, "__system_property_read", 
                                        (void *)my_system_property_read, 
                                        (void **)&orig_system_property_read);
                                        
                    // Hook get (兼容)
                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);
                    
                    LOGD("PLT Hook registered for %s", path);
                }
            }
        }
        fclose(fp);
        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(FinalModule)