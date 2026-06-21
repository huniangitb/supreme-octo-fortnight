#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>  // 添加 offsetof 支持

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[ERROR] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 使用抽象命名空间 socket，与 injector 匹配
#define IPC_SOCKET_NAME "nsp_ipc_socket"

// ==========================================
// 辅助函数：根据 UID 判断是否为用户应用
// ==========================================

static bool is_user_app(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    return (app_id >= 10000 && app_id < 20000) || app_id >= 99000;
}

// ==========================================
// Companion (Root 权限运行)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }
    buf[len] = '\0';

    char pkg_name[256];
    int pid = 0;
    int uid = 0;
    if (sscanf(buf, "REQ %255s %d %d", pkg_name, &pid, &uid) != 3) {
        close(client_fd);
        return;
    }

    // 转发给 Injector (使用抽象命名空间)
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';  // 抽象命名空间
        strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
        
        socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(inj_fd, (struct sockaddr*)&addr, addr_len) == 0) {
            char report_msg[512];
            int msg_len = snprintf(report_msg, sizeof(report_msg), 
                                 "REPORT %s %d %d", pkg_name, pid, uid);
            if (write(inj_fd, report_msg, msg_len) > 0) {
                LOGD("Companion: 已向 Injector 上报: %s (PID:%d, UID:%d)", 
                     pkg_name, pid, uid);
                char ack[16];
                read(inj_fd, ack, sizeof(ack));
            }
        }
        close(inj_fd);
    }

    write(client_fd, "OK", 2);
    close(client_fd);
}

// ==========================================
// Zygisk Module (App 进程运行)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 使用 UID 判断是否为用户应用
        if (!is_user_app(args->uid)) {
            return; 
        }

        const char* nice_name = NULL;
        if (args->nice_name != NULL) {
            nice_name = env->GetStringUTFChars(args->nice_name, NULL);
        }

        const char* final_name = nice_name ? nice_name : "unknown";
        int my_pid = getpid();

        LOGI("App [%s] (UID: %u): 上报至 Injector...", final_name, args->uid);

        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf), 
                                  "REQ %s %d %d", final_name, my_pid, args->uid);
            
            if (write(fd, req_buf, req_len) > 0) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                poll(&pfd, 1, 1000);
                LOGI("App [%s]: 上报完成", final_name);
            }
            close(fd);
        }

        if (nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 卸载模块库以保持纯净
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
