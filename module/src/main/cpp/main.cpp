#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

#include "zygisk.hpp"

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";

extern "C" const char* getprogname();

static void companion_handler(int client_fd) {
    auto send_and_close = [&](const char* msg) {
        write(client_fd, msg, strlen(msg));
        close(client_fd);
    };

    char buffer[256] = {0};
    if (read(client_fd, buffer, sizeof(buffer)) <= 0) {
        close(client_fd);
        return;
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {
        send_and_close("ERR_SOCKET_CREATE");
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(target_fd);
        send_and_close("ERR_PROXY_CONN");
        return;
    }

    write(target_fd, buffer, strlen(buffer));
    
    char ack[16] = {0};
    struct timeval tv = {1, 0};
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t ack_len = read(target_fd, ack, sizeof(ack));
    write(client_fd, (ack_len > 0) ? ack : "OK_TIMEOUT", (ack_len > 0) ? (size_t)ack_len : 10);

    close(target_fd);
    close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 1001) {
            this->companion_fd = -1;
            return;
        }
        this->companion_fd = api->connectCompanion();
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (this->companion_fd < 0) return;

        struct timeval tv = {1, 0};
        setsockopt(this->companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = getprogname();

        char buffer[256];
        snprintf(buffer, sizeof(buffer), "%s %d", process_name ? process_name : "unknown", getpid());
        
        write(this->companion_fd, buffer, strlen(buffer));

        char signal[32] = {0};
        read(this->companion_fd, signal, sizeof(signal) - 1);

        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
        close(this->companion_fd);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)