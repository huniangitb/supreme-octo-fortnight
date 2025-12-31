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

#define LOG_TAG "Zygisk_IPC_Reporter"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// Companion 逻辑：高权限运行，负责检查文件和转发
// -----------------------------------------------------------------------------
static void companion_handler(int client_fd) {
    // 1. 在高权限侧检查锁文件
    if (access(LOCK_FILE_PATH, F_OK) != 0) {
        write(client_fd, "SKIP", 4); // 通知 App 跳过等待
        close(client_fd);
        return;
    }

    char buffer[256] = {0};
    ssize_t len = read(client_fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {
        write(client_fd, "OK", 2);
        close(client_fd);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "OK", 2);
        close(target_fd);
        close(client_fd);
        return;
    }

    write(target_fd, buffer, len);

    char ack[16] = {0};
    ssize_t ack_len = read(target_fd, ack, sizeof(ack));
    write(client_fd, (ack_len > 0) ? ack : "OK", (ack_len > 0) ? ack_len : 2);

    close(target_fd);
    close(client_fd);
}

// -----------------------------------------------------------------------------
// Module 逻辑
// -----------------------------------------------------------------------------
class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        int app_id = args->uid % 100000;
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

        // 设置 1 秒超时，防止 Companion 侧逻辑卡死
        struct timeval tv = {1, 0};
        setsockopt(this->companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        const char* process_name = nullptr;
        bool need_release = false;
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            need_release = true;
        }
        if (!process_name) process_name = getprogname();
        if (!process_name) process_name = "unknown";

        // 发送数据
        char buffer[256];
        int msg_len = snprintf(buffer, sizeof(buffer), "%s %d", process_name, getpid());
        write(this->companion_fd, buffer, msg_len);

        // 阻塞等待信号
        char signal[16] = {0};
        ssize_t ret = read(this->companion_fd, signal, sizeof(signal));

        if (ret > 0 && strncmp(signal, "SKIP", 4) == 0) {
            LOGI("[Module] No lock file, skipping wait: %s", process_name);
        } else if (ret <= 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            LOGI("[Module] Timeout (1s), starting: %s", process_name);
        }

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

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)