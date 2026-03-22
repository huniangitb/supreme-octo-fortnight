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

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[ERROR] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 使用抽象命名空间 socket，与 injector 匹配
#define IPC_SOCKET_NAME "nsp_ipc_socket"
#define INJECTOR_SOCKET_TIMEOUT 2  // 2秒超时

// ==========================================
// 辅助函数：根据 UID 判断是否为用户应用
// ==========================================

static bool is_user_app(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    return (app_id >= 10000 && app_id < 20000) || app_id >= 99000;
}

// ==========================================
// 辅助函数：发送消息给 Injector
// ==========================================

static bool send_to_injector(const char* pkg_name, int pid, uint32_t uid) {
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd < 0) {
        LOGE("创建 socket 失败: %s", strerror(errno));
        return false;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';  // 抽象命名空间
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
    
    // 设置超时
    struct timeval tv = { .tv_sec = INJECTOR_SOCKET_TIMEOUT, .tv_usec = 0 };
    setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(inj_fd, (struct sockaddr*)&addr, addr_len) < 0) {
        LOGE("连接 Injector 失败: %s (可能 Injector 未运行)", strerror(errno));
        close(inj_fd);
        return false;
    }
    
    // 使用 REPORT 格式，与 Injector 期望匹配
    char report_msg[512];
    int msg_len = snprintf(report_msg, sizeof(report_msg), 
                         "REPORT %s %d %d", pkg_name, pid, uid);
    
    LOGD("向 Injector 发送: %s", report_msg);
    
    ssize_t written = write(inj_fd, report_msg, msg_len);
    if (written != msg_len) {
        LOGE("写入 Injector 失败: %s", strerror(errno));
        close(inj_fd);
        return false;
    }
    
    // 等待 Injector 确认
    char ack[16];
    ssize_t read_len = read(inj_fd, ack, sizeof(ack) - 1);
    if (read_len > 0) {
        ack[read_len] = '\0';
        LOGD("收到 Injector 确认: %s", ack);
        if (strcmp(ack, "OK") == 0) {
            close(inj_fd);
            return true;
        }
    } else {
        LOGD("未收到 Injector 确认 (可能 Injector 忙，但消息已发送)");
        // 即使没有收到确认，消息也可能已处理，继续执行
    }
    
    close(inj_fd);
    return true;  // 假设成功，因为消息已发送
}

// ==========================================
// Companion (Root 权限运行)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        LOGE("读取客户端消息失败: %s", strerror(errno));
        close(client_fd);
        return;
    }
    buf[len] = '\0';
    
    LOGD("Companion 收到消息: %s", buf);
    
    char pkg_name[256];
    int pid = 0;
    int uid = 0;
    
    // 支持两种格式：REQ 和 REPORT (兼容性)
    if (sscanf(buf, "REQ %255s %d %d", pkg_name, &pid, &uid) != 3 &&
        sscanf(buf, "REPORT %255s %d %d", pkg_name, &pid, &uid) != 3) {
        LOGE("Companion 收到无效消息格式: %s", buf);
        close(client_fd);
        return;
    }
    
    LOGI("Companion 处理请求: %s (PID:%d, UID:%d)", pkg_name, pid, uid);
    
    // 转发给 Injector
    bool success = send_to_injector(pkg_name, pid, uid);
    
    // 发送响应给 Zygisk 模块
    const char* response = success ? "OK" : "FAIL";
    write(client_fd, response, strlen(response));
    close(client_fd);
    
    if (success) {
        LOGD("Companion: 成功上报 %s (PID:%d, UID:%d)", pkg_name, pid, uid);
    } else {
        LOGE("Companion: 上报 %s 失败", pkg_name);
    }
}

// ==========================================
// Zygisk Module (App 进程运行)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGD("AppReporterModule 已加载");
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 检查是否是系统应用
        if (!is_user_app(args->uid)) {
            LOGD("跳过系统应用/服务 (UID: %u)", args->uid);
            return;
        }
        
        const char* nice_name = NULL;
        if (args->nice_name != NULL) {
            nice_name = env->GetStringUTFChars(args->nice_name, NULL);
        }
        
        const char* final_name = nice_name ? nice_name : "unknown";
        int my_pid = getpid();
        
        LOGI("========================================");
        LOGI("检测到应用启动: %s (PID: %d, UID: %u)", final_name, my_pid, args->uid);
        LOGI("正在向 Namespace-Proxy 上报...");
        
        // 连接 Companion 进程
        int fd = api->connectCompanion();
        if (fd < 0) {
            LOGE("无法连接 Companion 进程: %s", strerror(errno));
            if (nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
            return;
        }
        
        // 使用 REQ 格式发送给 Companion
        char req_buf[512];
        int req_len = snprintf(req_buf, sizeof(req_buf), 
                              "REQ %s %d %d", final_name, my_pid, args->uid);
        
        LOGD("向 Companion 发送: %s", req_buf);
        
        if (write(fd, req_buf, req_len) != req_len) {
            LOGE("向 Companion 写入失败: %s", strerror(errno));
            close(fd);
            if (nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
            return;
        }
        
        // 等待 Companion 响应 (最多等待 2 秒)
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 2000);
        
        if (poll_ret > 0 && (pfd.revents & POLLIN)) {
            char response[16];
            ssize_t n = read(fd, response, sizeof(response) - 1);
            if (n > 0) {
                response[n] = '\0';
                LOGI("Companion 响应: %s", response);
                if (strcmp(response, "OK") == 0) {
                    LOGI("✓ 应用 %s 已成功上报给 Namespace-Proxy", final_name);
                } else {
                    LOGI("⚠ 应用 %s 上报失败: %s", final_name, response);
                }
            }
        } else if (poll_ret == 0) {
            LOGD("Companion 响应超时 (2秒)，可能注入器繁忙，继续启动流程");
        } else {
            LOGE("Companion poll 失败: %s", strerror(errno));
        }
        
        close(fd);
        LOGI("========================================");
        
        if (nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 卸载模块库以保持纯净，减少对应用的干扰
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        LOGD("模块已卸载，应用将正常运行");
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
