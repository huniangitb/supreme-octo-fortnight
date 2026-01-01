#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_Blocker"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// Companion 逻辑 (运行在 root/magisk 上下文)
// -----------------------------------------------------------------------------
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    // 1. 必须先读取 App 发送的数据，确保握手建立
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd);
        return;
    }

    // 2. 检查锁文件：如果不存在，直接写回并退出
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        write(client_fd, "SKIP", 4);
        close(client_fd);
        return;
    }

    // 3. 连接外部代理
    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {
        write(client_fd, "ERR_SOCK", 8);
        close(client_fd);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // 尝试连接 Proxy
    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "ERR_CONN", 8);
        close(target_fd);
        close(client_fd);
        return;
    }

    // 4. 转发给 Proxy 并等待 Proxy 的回复
    write(target_fd, buffer, strlen(buffer));
    
    char ack[16] = {0};
    ssize_t ack_len = read(target_fd, ack, sizeof(ack)); // 阻塞直到 Proxy 响应

    // 5. 将 Proxy 的响应（或 OK）传回给 App
    if (ack_len > 0) {
        write(client_fd, ack, ack_len);
    } else {
        write(client_fd, "OK", 2);
    }

    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module 逻辑 (运行在 App 进程)
// -----------------------------------------------------------------------------
class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        uint32_t app_id = args->uid % 100000;
        if (app_id < 10000) {
            this->companion_fd = -1;
            return;
        }
        this->companion_fd = api->connectCompanion();
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;

        // 设置读取超时 1 秒
        struct timeval tv = {1, 0};
        setsockopt(this->companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        const char* process_name = nullptr;
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        if (!process_name) process_name = getprogname();

        // 1. 发送同步信号和数据
        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", getpid());
        write(this->companion_fd, buffer, msg_len);

        // 2. 进入阻塞等待
        LOGI("[Module] Blocking process: %s", process_name);
        char signal[16] = {0};
        // read 会阻塞直到 Companion 写入数据或 1秒超时
        ssize_t ret = read(this->companion_fd, signal, sizeof(signal));

        if (ret > 0) {
            LOGI("[Module] Released by signal: %s (msg: %s)", process_name, signal);
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            LOGI("[Module] 1s timeout reached, forcing release: %s", process_name);
        } else {
            LOGI("[Module] Connection closed, releasing: %s", process_name);
        }

        // 3. 清理
        if (process_name && args->nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
        close(this->companion_fd);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)