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
#include <stddef.h>

#include "zygisk.hpp"

#define LOG_TAG "NSP_Zygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define IPC_SOCKET_NAME "nsp_ipc_socket"

// 判定是否为需要注入的应用 UID
static bool is_target_uid(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    // 普通应用 (10000-19999) 或 某些系统的特定应用范围
    return (app_id >= 10000 && app_id < 20000) || (app_id >= 99000);
}

// ==========================================
// Companion (Root 权限运行，负责中转)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[512];
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 300000 }; // 300ms 超时
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }
    buf[len] = '\0';

    // 转发给后台 Injector 服务
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        addr.sun_path[0] = '\0'; // 抽象命名空间
        memcpy(addr.sun_path + 1, IPC_SOCKET_NAME, strlen(IPC_SOCKET_NAME));
        socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);

        // 设置极短的发送/连接超时，避免阻塞应用
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(inj_fd, (struct sockaddr*)&addr, addr_len) == 0) {
            // 将 REQ 转换为 REPORT 协议发送
            char report_msg[512];
            char pkg[256];
            int pid, uid;
            if (sscanf(buf, "REQ %s %d %d", pkg, &pid, &uid) == 3) {
                int r_len = snprintf(report_msg, sizeof(report_msg), "REPORT %s %d %d", pkg, pid, uid);
                write(inj_fd, report_msg, r_len);
                
                // 尝试读一个确认包，但不强求
                char ack[8];
                read(inj_fd, ack, sizeof(ack));
            }
        }
        close(inj_fd);
    }

    write(client_fd, "OK", 2);
    close(client_fd);
}

// ==========================================
// Zygisk Module (注入 App 进程执行)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!is_target_uid(args->uid)) return;

        const char* nice_name = nullptr;
        if (args->nice_name != nullptr) {
            nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }

        if (!nice_name || strlen(nice_name) == 0) {
            if (nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
            return;
        }

        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf), "REQ %s %d %d", nice_name, getpid(), args->uid);
            
            // 发送通知
            write(fd, req_buf, req_len);

            // 限制等待响应的时间，防止 Companion 卡死导致 App 启动黑屏
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 200) > 0) {
                char dummy[8];
                read(fd, dummy, sizeof(dummy));
            }
            close(fd);
        }

        if (nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 完成任务后立即卸载本库，减少内存占用
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
