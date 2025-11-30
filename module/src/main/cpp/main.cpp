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

// 目标外部 Socket 路径
static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// Companion (服务端) 逻辑 - 运行在 Root 环境下
// -----------------------------------------------------------------------------
// 这个函数负责：接收 App 发来的数据 -> 转发给外部 Socket -> 关闭连接
static void companion_handler(int client_fd) {
    // 1. 读取 APP 发来的消息
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }
    
    // 收到消息，打印一下
    LOGD("[Companion] Received from App: %s", buffer);

    // 2. 连接真正的外部 Socket (/data/Namespace-Proxy/ipc.sock)
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
        LOGW("[Companion] Failed to connect to proxy server: %s", strerror(errno));
        // 这里可以选择不回复客户端，直接断开
        close(target_fd);
        close(client_fd);
        return;
    }

    // 3. 转发数据
    write(target_fd, buffer, len);
    LOGI("[Companion] Forwarded to Proxy: %s", buffer);

    // 4. 清理
    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module (客户端) 逻辑 - 运行在 APP 进程内
// -----------------------------------------------------------------------------

class NamespaceProxyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->companion_fd = -1;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // [关键步骤 1] 在沙盒生效前，连接 Companion (Root 进程)
        // 这个 fd 会被保留到 postAppSpecialize 使用
        this->companion_fd = api->connectCompanion();

        if (this->companion_fd < 0) {
            LOGE("[Module] Failed to connect to Companion!");
        }

        // [隐藏] 
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 如果连接 Companion 失败，直接退出
        if (this->companion_fd < 0) return;

        // 1. 获取包名
        const char* process_name = nullptr;
        bool need_release = false;

        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            need_release = true;
        }
        if (process_name == nullptr) process_name = getprogname();
        if (process_name == nullptr) process_name = "unknown";

        // 2. 过滤系统进程
        if (strstr(process_name, "zygote") != nullptr || 
            strcmp(process_name, "app_process") == 0 || 
            strcmp(process_name, "app_process64") == 0) {
            
            if (need_release && args->nice_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
            close(this->companion_fd); // 别忘了关闭 fd
            return; 
        }

        LOGI("[Module] Process specialized: %s. Sending to companion...", process_name);

        // 3. 格式化数据并通过 companion_fd 发送
        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name, getpid());
        
        if (msg_len > 0) {
            write(this->companion_fd, buffer, msg_len);
        }

        // 4. 清理资源
        close(this->companion_fd); // 发送完即可关闭
        if (need_release && args->nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd; // 保存通往 Root 进程的文件描述符
};

// 注册模块
REGISTER_ZYGISK_MODULE(NamespaceProxyModule)

// [关键步骤 2] 注册 Companion 处理函数
REGISTER_ZYGISK_COMPANION(companion_handler)