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

#include "zygisk.hpp"

// 使用 LOG 定义，确保日志输出
#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[ERROR] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

// ==========================================
// 纯 C 辅助函数
// ==========================================

static bool is_target_process(const char* name) {
    if (name == NULL) return false;
    
    // 目标进程列表
    const char* targets[] = {
        "com.android.providers.media",
        "android.process.media",
        "com.google.android.providers.media",
        "com.android.providers.media.module"
    };
    
    size_t num_targets = sizeof(targets) / sizeof(targets[0]);
    for (size_t i = 0; i < num_targets; i++) {
        if (strstr(name, targets[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// ==========================================
// Companion (以 Root 权限在独立进程运行)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[1024];
    // 1. 读取来自 App 进程的请求
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }
    buf[len] = '\0';

    char pkg_name[256];
    int pid = 0;
    // 解析指令 "REQ <package> <pid>"
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        LOGE("Companion: 无法解析请求内容: %s", buf);
        close(client_fd);
        return;
    }

    LOGI("Companion: 收到上报请求 - App: %s, PID: %d", pkg_name, pid);

    // 2. 连接 Injector 的 Unix Domain Socket
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd < 0) {
        LOGE("Companion: 创建 Socket 失败: %s", strerror(errno));
    } else {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        // 设置连接和读写超时（1.5秒）
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 500000;
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(inj_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report_msg[512];
            int msg_len = snprintf(report_msg, sizeof(report_msg), "REPORT %s %d", pkg_name, pid);
            
            if (write(inj_fd, report_msg, msg_len) > 0) {
                LOGD("Companion: 已成功转发 REPORT 给 Injector");
                
                // 尝试读取一次确认（防止 Injector 还没处理完连接就断了）
                char dummy_resp[16];
                read(inj_fd, dummy_resp, sizeof(dummy_resp));
            } else {
                LOGE("Companion: 转发 REPORT 失败: %s", strerror(errno));
            }
        } else {
            LOGE("Companion: 连接 Injector 失败 (%s): %s", INJECTOR_SOCKET_PATH, strerror(errno));
        }
        close(inj_fd);
    }

    // 3. 告知 App 进程 Companion 已处理完毕
    const char* ok_msg = "DONE";
    write(client_fd, ok_msg, strlen(ok_msg));
    close(client_fd);
}

// ==========================================
// Zygisk Module (在 App 进程中运行)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    // 虽然是类成员，但内部全部使用 C 逻辑
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->nice_name == NULL) return;

        // C 风格 JNI 调用获取包名
        const char* nice_name_c = env->GetStringUTFChars(args->nice_name, NULL);
        if (nice_name_c == NULL) return;

        // 仅针对目标进程进行上报
        if (is_target_process(nice_name_c)) {
            int my_pid = getpid();
            LOGI("App [%s]: 准备向 Companion 上报...", nice_name_c);

            // 连接 Companion
            int fd = api->connectCompanion();
            if (fd >= 0) {
                char req_buf[512];
                int req_len = snprintf(req_buf, sizeof(req_buf), "REQ %s %d", nice_name_c, my_pid);
                
                if (write(fd, req_buf, req_len) > 0) {
                    // 使用 poll 阻塞等待 Companion 完成转发逻辑
                    struct pollfd pfd;
                    pfd.fd = fd;
                    pfd.events = POLLIN;
                    if (poll(&pfd, 1, 2000) > 0) {
                        LOGI("App [%s]: 上报流程结束", nice_name_c);
                    } else {
                        LOGE("App [%s]: 上报等待超时", nice_name_c);
                    }
                }
                close(fd);
            } else {
                LOGE("App [%s]: 无法连接 Companion", nice_name_c);
            }
        }

        env->ReleaseStringUTFChars(args->nice_name, nice_name_c);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 上报完成后立即卸载模块库，释放内存，并确保不留下任何 Hook
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// 宏定义会处理必要的 C/C++ 导出符号
REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)