#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_IPC_Reporter"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// 目标外部 Socket 路径
static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// Companion (服务端中转) 逻辑
// 职责：接收 App 进程数据，原封不动地转发给外部代理服务
// -----------------------------------------------------------------------------
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }

    // 连接外部代理服务
    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {
        LOGE("[Companion] Failed to create socket: %s", strerror(errno));
        close(client_fd);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGW("[Companion] Failed to connect to proxy server at %s: %s", TARGET_SOCKET_PATH, strerror(errno));
        close(target_fd);
        close(client_fd);
        return;
    }

    // 转发数据
    write(target_fd, buffer, len);
    LOGI("[Companion] Forwarded to proxy: %s", buffer);

    // 清理
    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module (客户端) 逻辑
// 职责：上报所有非核心系统进程的信息
// -----------------------------------------------------------------------------

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->companion_fd = -1;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // [核心过滤]
        // Android 应用的 UID 从 10000 开始。
        // UID < 10000 的是系统核心组件 (system_server, nfc, bluetooth 等)。
        // 我们只关心应用进程，所以过滤掉这些核心组件。
        int app_id = args->uid % 100000;
        if (app_id <= 10000) {
            return; // 忽略核心系统进程，不建立连接
        }

        // 对于所有应用进程 (UID >= 10000)，都尝试连接 Companion
        this->companion_fd = api->connectCompanion();
        if (this->companion_fd < 0) {
            LOGE("[Module] Failed to connect to Companion for UID %d!", args->uid);
        }
        
        // [隐藏模块]
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 如果 pre 阶段没有成功建立连接（因为被 UID 过滤或连接失败），直接退出
        if (this->companion_fd < 0) {
            return;
        }

        // 获取进程名 (包名)
        const char* process_name = nullptr;
        bool need_release = false;
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            need_release = true;
        }
        if (process_name == nullptr) {
            process_name = getprogname();
        }
        if (process_name == nullptr) {
            process_name = "unknown";
        }

        LOGI("[Module] Reporting process: %s (PID: %d)", process_name, getpid());

        // 格式化 "包名 PID" 字符串并发送给 Companion
        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name, getpid());
        if (msg_len > 0) {
            write(this->companion_fd, buffer, msg_len);
        }

        // 清理资源
        close(this->companion_fd);
        if (need_release && args->nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;
};

// 注册模块和 Companion
REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)