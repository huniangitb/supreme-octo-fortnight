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
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <ctype.h>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "[ERROR] " __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

// ==========================================
// 辅助函数
// ==========================================

// 判断是否为目标进程（可以根据需求修改，或者直接返回 true 以支持所有应用）
static bool is_target_process(const char* name) {
    if (!name) return false;
    // 默认保留原有的媒体进程过滤，如果需要上报所有应用，请直接返回 true
    const char* targets[] = {
        "com.android.providers.media",
        "android.process.media",
        "com.google.android.providers.media",
        "com.android.providers.media.module"
    };
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        if (strstr(name, targets[i])) return true;
    }
    return false;
}

// ==========================================
// Companion (Root 权限运行)
// ==========================================
// 此函数在 root 进程中运行，负责转发 App 的请求给 Injector 守护进程

static void companion_handler(int client_fd) {
    char buf[1024];
    // 1. 读取 App 发来的请求 (格式: "REQ pkg_name pid")
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) { 
        close(client_fd); 
        return; 
    }
    buf[len] = '\0';
    
    char pkg_name[256];
    int pid = 0;
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        LOGE("Companion: 请求格式解析失败: %s", buf);
        close(client_fd); 
        return;
    }
    
    LOGI("Companion: 准备上报进程: %s (PID: %d)", pkg_name, pid);

    // 2. 连接外部 Injector Socket 并发送 REPORT
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);
        
        // 设置短超时
        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 }; 
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(inj_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d", pkg_name, pid);
            
            if (write(inj_fd, report, strlen(report)) > 0) {
                LOGD("Companion: 已向 Injector 发送 REPORT 指令");
                
                // 等待 Injector 确认（可选）
                char resp[32];
                ssize_t n = read(inj_fd, resp, sizeof(resp) - 1);
                if (n > 0) {
                    resp[n] = '\0';
                    LOGD("Companion: Injector 响应: %s", resp);
                }
            }
        } else {
            LOGE("Companion: 无法连接 Injector (%s): %s", INJECTOR_SOCKET_PATH, strerror(errno));
        }
        close(inj_fd);
    } else {
        LOGE("Companion: 创建 Socket 失败: %s", strerror(errno));
    }
    
    // 3. 回复 App 表示处理完成
    const char* ack = "OK";
    write(client_fd, ack, strlen(ack));
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
        // 获取进程名
        const char* proc_raw = nullptr;
        if (args->nice_name) proc_raw = env->GetStringUTFChars(args->nice_name, nullptr);
        
        char* pkg = proc_raw ? strdup(proc_raw) : strdup("unknown");
        int my_pid = getpid();
        
        if (proc_raw) env->ReleaseStringUTFChars(args->nice_name, proc_raw);

        // 过滤是否需要上报
        if (!is_target_process(pkg)) {
            free(pkg);
            return;
        }

        LOGI("App [%s]: 启动上报流程...", pkg);

        // 通过 Companion 进行上报
        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req[512];
            snprintf(req, sizeof(req), "REQ %s %d", pkg, my_pid);
            
            if (write(fd, req, strlen(req)) > 0) {
                // 等待 Companion 完成处理（避免同步问题）
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                if (poll(&pfd, 1, 2000) > 0) {
                    LOGI("App [%s]: 上报成功", pkg);
                } else {
                    LOGE("App [%s]: 上报超时", pkg);
                }
            } else {
                LOGE("App [%s]: 写入 Companion 失败: %s", pkg, strerror(errno));
            }
            close(fd);
        } else {
            LOGE("App [%s]: 无法连接 Companion", pkg);
        }
        
        free(pkg);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 由于不再需要 Hook 逻辑，上报完成后可以卸载该库以节省资源
        // 如果你需要后续的定时轮询（Hot Reload），请删除下面这一行
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
};

// 注册 Zygisk 模块和 Companion 处理函数
REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)