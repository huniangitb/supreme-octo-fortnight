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

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[ERROR] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

// ==========================================
// 辅助函数：根据 UID 判断是否为用户应用
// ==========================================

static bool is_user_app(uint32_t uid) {
    // Android 用户应用 UID 从 10000 开始
    // 对于多用户环境（如用户 10），UID 会是 1010001
    // 取模 100000 可以得到其在当前用户下的基础应用 ID
    uint32_t app_id = uid % 100000;
    
    // 10000 (AID_APP_START) 到 19999 (AID_APP_END) 是普通 App
    // 99000 (AID_ISOLATED_START) 以上是隔离进程 (如 Chrome Render)
    return (app_id >= 10000);
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
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        close(client_fd);
        return;
    }

    // 转发给 Injector
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(inj_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report_msg[512];
            int msg_len = snprintf(report_msg, sizeof(report_msg), "REPORT %s %d", pkg_name, pid);
            if (write(inj_fd, report_msg, msg_len) > 0) {
                LOGD("Companion: 已向 Injector 上报用户应用: %s (PID:%d)", pkg_name, pid);
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
        // 核心改动：根据 UID 判断
        if (!is_user_app(args->uid)) {
            return; 
        }

        const char* nice_name_c = NULL;
        if (args->nice_name != NULL) {
            nice_name_c = env->GetStringUTFChars(args->nice_name, NULL);
        }

        const char* final_name = nice_name_c ? nice_name_c : "unknown_user_app";
        int my_pid = getpid();

        LOGI("App [%s] (UID: %u): 识别为用户应用，发起上报...", final_name, args->uid);

        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf), "REQ %s %d", final_name, my_pid);
            
            if (write(fd, req_buf, req_len) > 0) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                poll(&pfd, 1, 1000); // 等待处理确认
                LOGI("App [%s]: 上报流程完成", final_name);
            }
            close(fd);
        }

        if (nice_name_c) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name_c);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 执行完上报逻辑后，卸载自身以保证系统纯净
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)