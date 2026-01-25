#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>  // 添加这一行以获取snprintf

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_Minimal"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

extern "C" const char* getprogname();

static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    
    if (n <= 0) {
        close(client_fd);
        return;
    }

    // 连接到后端服务
    int backend_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (backend_fd < 0) {
        const char* err_msg = "ERR_SOCKET";
        write(client_fd, err_msg, strlen(err_msg));
        close(client_fd);
        return;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(backend_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        const char* err_msg = "ERR_CONNECT";
        write(client_fd, err_msg, strlen(err_msg));
        close(backend_fd);
        close(client_fd);
        return;
    }

    // 转发请求
    write(backend_fd, buffer, strlen(buffer));
    
    // 读取响应
    char response[64] = {0};
    ssize_t resp_len = read(backend_fd, response, sizeof(response) - 1);
    if (resp_len > 0) {
        write(client_fd, response, resp_len);
    } else {
        write(client_fd, "OK", 2);
    }

    close(backend_fd);
    close(client_fd);
}

class MinimalModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 只处理应用进程 (UID >= 10000)
        if (args->uid < 10000) {
            return;
        }
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        int fd = api->connectCompanion();
        if (fd < 0) return;

        const char* process_name = nullptr;
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        if (!process_name) {
            process_name = getprogname();
        }

        char report[256];
        snprintf(report, sizeof(report), "%s %d", 
                 process_name ? process_name : "unknown", getpid());

        write(fd, report, strlen(report));

        // 等待响应
        char response[32] = {0};
        read(fd, response, sizeof(response) - 1);

        if (args->nice_name && process_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
        
        close(fd);
        
        // 卸载模块库
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

extern "C" {
    REGISTER_ZYGISK_MODULE(MinimalModule)
    REGISTER_ZYGISK_COMPANION(companion_handler)
}