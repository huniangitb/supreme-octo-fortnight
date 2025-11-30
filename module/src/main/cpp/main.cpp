#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <vector>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_IPC"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
extern "C" const char* getprogname();

// Companion (服务端) 逻辑 - 保持不变
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) { close(client_fd); return; }
    
    LOGD("[Companion] Received from App: %s", buffer);

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) { close(client_fd); return; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGW("[Companion] Failed to connect to proxy: %s", strerror(errno));
        close(target_fd);
        close(client_fd);
        return;
    }
    write(target_fd, buffer, len);
    LOGI("[Companion] Forwarded to Proxy: %s", buffer);
    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module (客户端) 逻辑
// -----------------------------------------------------------------------------

class NamespaceProxyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->companion_fd = -1;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // [过滤第一步]：通过 UID 快速过滤掉核心系统服务
        int app_id = args->uid % 100000;
        if (app_id < 10000) {
            return; // 是系统服务，不是应用，直接跳过
        }

        // [过滤第二步]：通过 ApplicationInfo.flags 过滤掉预装的系统应用
        if (!isUserApp(args->nice_name)) {
            // 是系统应用 (如相机、设置)，跳过
            const char* pkg_name_c = env->GetStringUTFChars(args->nice_name, nullptr);
            LOGD("[Module] Skipping system app: %s", pkg_name_c);
            env->ReleaseStringUTFChars(args->nice_name, pkg_name_c);
            return;
        }

        // 只有用户安装的应用才会执行到这里
        this->companion_fd = api->connectCompanion();
        if (this->companion_fd < 0) {
            LOGE("[Module] Failed to connect to Companion!");
        }

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return; // 如果被过滤了，fd 为 -1，直接退出

        const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        LOGI("[Module] User App specialized: %s (UID: %d). Sending...", process_name, args->uid);

        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name, getpid());
        if (msg_len > 0) {
            write(this->companion_fd, buffer, msg_len);
        }

        close(this->companion_fd);
        env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;

    // JNI 辅助函数，检查一个包名是否为用户应用
    bool isUserApp(jstring packageName) {
        if (packageName == nullptr) return false;

        // 获取 ActivityThread -> Context -> PackageManager
        jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
        if (!activityThreadClass) return false;
        jmethodID currentActivityThreadMethod = env->GetStaticMethodID(activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
        if (!currentActivityThreadMethod) return false;
        jobject activityThread = env->CallStaticObjectMethod(activityThreadClass, currentActivityThreadMethod);
        if (!activityThread) return false;
        jmethodID getSystemContextMethod = env->GetMethodID(activityThreadClass, "getSystemContext", "()Landroid/content/Context;");
        if (!getSystemContextMethod) return false;
        jobject context = env->CallObjectMethod(activityThread, getSystemContextMethod);
        if (!context) return false;
        jclass contextClass = env->GetObjectClass(context);
        jmethodID getPackageManagerMethod = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
        if (!getPackageManagerMethod) return false;
        jobject packageManager = env->CallObjectMethod(context, getPackageManagerMethod);
        if (!packageManager) return false;

        // 获取 ApplicationInfo
        jclass packageManagerClass = env->GetObjectClass(packageManager);
        jmethodID getApplicationInfoMethod = env->GetMethodID(packageManagerClass, "getApplicationInfo", "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
        if (!getApplicationInfoMethod) return false;
        jobject applicationInfo = env->CallObjectMethod(packageManager, getApplicationInfoMethod, packageName, 0 /* flags */);

        if (env->ExceptionCheck() || !applicationInfo) {
            env->ExceptionClear();
            return false; // 获取失败，当作系统应用处理
        }

        // 获取 flags 字段
        jclass applicationInfoClass = env->GetObjectClass(applicationInfo);
        jfieldID flagsField = env->GetFieldID(applicationInfoClass, "flags", "I");
        jint flags = env->GetIntField(applicationInfo, flagsField);

        // 定义 FLAG_SYSTEM 和 FLAG_UPDATED_SYSTEM_APP 的值
        // (直接用硬编码值比 JNI 查找静态字段更快更简单)
        const int FLAG_SYSTEM = 1;
        const int FLAG_UPDATED_SYSTEM_APP = 128;

        // 如果 flags 中包含 FLAG_SYSTEM 或 FLAG_UPDATED_SYSTEM_APP，则为系统应用
        return (flags & (FLAG_SYSTEM | FLAG_UPDATED_SYSTEM_APP)) == 0;
    }
};

REGISTER_ZYGISK_MODULE(NamespaceProxyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)