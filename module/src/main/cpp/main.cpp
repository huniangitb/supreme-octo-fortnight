#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <string>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_IPC"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
extern "C" const char* getprogname();

// Companion 逻辑 (不变)
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) { close(client_fd); return; }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) { close(client_fd); return; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        close(client_fd);
        return;
    }
    write(target_fd, buffer, len);
    LOGI("[Companion] Forwarded: %s", buffer);
    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module 逻辑
// -----------------------------------------------------------------------------

class NamespaceProxyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->companion_fd = -1;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // [Stage 1] 基础 UID 过滤
        // 过滤掉 Root(0), System(1000), Shell(2000) 等核心进程
        int app_id = args->uid % 100000;
        if (app_id < 10000) return;

        // 预先连接 Companion，但不做复杂的应用类型判断
        this->companion_fd = api->connectCompanion();
        
        // 隐藏模块
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;

        // [Stage 2] 精确过滤：使用 Android API 判断是否为系统应用
        // 此时 ART 环境已就绪，JNI 调用是安全的
        if (!isUserApp(args->app_data_dir)) {
            // 是系统应用，断开连接并退出
            close(this->companion_fd);
            return;
        }

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        LOGI("[Module] User App Detected: %s (PID: %d)", process_name, getpid());

        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name, getpid());
        if (msg_len > 0) {
            write(this->companion_fd, buffer, msg_len);
        }

        close(this->companion_fd);
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;

    // -------------------------------------------------------------------------
    // 准确判断是否为用户应用
    // 策略：检查 ApplicationInfo.flags
    // -------------------------------------------------------------------------
    bool isUserApp(jstring appDataDir) {
        // 1. 获取 ActivityThread
        jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
        if (!activityThreadClass) { env->ExceptionClear(); return false; }

        jmethodID currentActivityThread = env->GetStaticMethodID(activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
        jobject at = env->CallStaticObjectMethod(activityThreadClass, currentActivityThread);
        if (!at) { env->ExceptionClear(); return false; }

        // 2. 获取 Application (Context)
        jmethodID getApplication = env->GetMethodID(activityThreadClass, "getApplication", "()Landroid/app/Application;");
        jobject context = env->CallObjectMethod(at, getApplication);
        if (!context) { env->ExceptionClear(); return false; }

        // 3. 获取 ApplicationInfo
        jclass contextClass = env->GetObjectClass(context);
        jmethodID getAppInfo = env->GetMethodID(contextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
        jobject appInfo = env->CallObjectMethod(context, getAppInfo);
        if (!appInfo) { env->ExceptionClear(); return false; }

        // 4. 检查 flags
        jclass appInfoClass = env->GetObjectClass(appInfo);
        jfieldID flagsField = env->GetFieldID(appInfoClass, "flags", "I");
        jint flags = env->GetIntField(appInfo, flagsField);

        // FLAG_SYSTEM = 1
        // FLAG_UPDATED_SYSTEM_APP = 128
        bool isSystem = (flags & 1) != 0;
        bool isUpdatedSystem = (flags & 128) != 0;

        // 如果是 系统应用 或 升级后的系统应用，则返回 false (过滤掉)
        if (isSystem || isUpdatedSystem) {
            return false;
        }

        return true;
    }
};

REGISTER_ZYGISK_MODULE(NamespaceProxyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)