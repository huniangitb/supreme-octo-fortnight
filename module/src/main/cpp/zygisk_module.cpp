#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_Blocker"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

// 后端 Socket 路径
static const char* BACKEND_SOCK = "/data/Namespace-Proxy/ipc.sock";

// --- 硬编码规则列表 ---
static const char* BLOCK_LIST[] = {
    "/storage/emulated/0/Download/1DMP",
    // 你可以在这里添加更多硬编码路径
    
    nullptr // 必须以 nullptr 结尾
};

// --- 原始函数指针 ---
static int (*orig_openat)(int, const char*, int, mode_t) = nullptr;
static int (*orig_mkdirat)(int, const char*, mode_t) = nullptr;

extern "C" const char* getprogname();

// --- 拦截判断逻辑 ---
static bool is_blocked(const char* path) {
    if (!path) return false;
    for (int i = 0; BLOCK_LIST[i] != nullptr; i++) {
        if (strstr(path, BLOCK_LIST[i])) return true;
    }
    return false;
}

// --- Hook 函数 ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (is_blocked(path)) {
        LOGI("已拦截 Open: %s", path);
        errno = ENOENT;
        return -1;
    }
    return orig_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (is_blocked(path)) {
        LOGI("已拦截 Mkdir: %s", path);
        errno = EACCES;
        return -1;
    }
    return orig_mkdirat(fd, path, mode);
}

// --- Companion 逻辑 (Root 权限下运行) ---
static void companion_handler(int client_fd) {
    char buffer[256] = {0};
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    // 尝试连接后端
    int backend_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (backend_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, BACKEND_SOCK, sizeof(addr.sun_path) - 1);

        if (connect(backend_fd, (struct sockaddr*)&addr, sizeof(addr)) >= 0) {
            // 将汇报信息转发给后端
            write(backend_fd, buffer, strlen(buffer));
            // 简单等待一个响应或直接关闭
            char ack[8];
            read(backend_fd, ack, sizeof(ack));
        }
        close(backend_fd);
    }
    
    // 给 App 一个反馈并关闭
    write(client_fd, "OK", 2);
    close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // UID 过滤，仅处理普通应用和 Media 进程
        if (args->uid < 1001) return;

        const char* process = nullptr;
        if (args->nice_name) {
            process = env->GetStringUTFChars(args->nice_name, nullptr);
        } else {
            process = getprogname();
        }

        if (process) {
            // 识别 Media Provider
            if (strstr(process, "android.providers.media") || 
                strstr(process, "android.process.media") ||
                strstr(process, "com.google.android.providers.media")) {
                this->should_hook = true;
            }
            
            // 记录进程名用于 postApp 阶段汇报
            strncpy(this->proc_name, process, sizeof(this->proc_name) - 1);

            if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, process);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 1. 执行 Hook (如果是 Media 进程)
        if (this->should_hook) {
            void* sym_openat = DobbySymbolResolver("libc.so", "openat");
            void* sym_mkdirat = DobbySymbolResolver("libc.so", "mkdirat");
            if (sym_openat && sym_mkdirat) {
                DobbyHook(sym_openat, (dobby_dummy_func_t)my_openat, (dobby_dummy_func_t*)&orig_openat);
                DobbyHook(sym_mkdirat, (dobby_dummy_func_t)my_mkdirat, (dobby_dummy_func_t*)&orig_mkdirat);
                LOGI("[%s] 硬编码 Hook 已就绪", this->proc_name);
            }
        }

        // 2. 向后端汇报进程启动
        int fd = api->connectCompanion();
        if (fd >= 0) {
            char buf[300];
            // 格式: 进程名 PID
            snprintf(buf, sizeof(buf), "%s %d", this->proc_name, getpid());
            write(fd, buf, strlen(buf));
            
            // 设置一个简短的读取超时，防止挂死应用启动
            struct timeval tv = {0, 500000}; // 500ms
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            char ack[8];
            read(fd, ack, sizeof(ack)); 
            
            close(fd);
        }

        // 卸载模块库释放内存
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    bool should_hook = false;
    char proc_name[256] = "unknown";
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)