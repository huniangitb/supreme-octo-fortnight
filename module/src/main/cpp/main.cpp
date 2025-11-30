#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>

// 引入 Zygisk V4 头文件
#include "zygisk.hpp"

// 定义日志 TAG 和宏
#define LOG_TAG "Zygisk_IPC"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// 获取进程名的系统函数声明
extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// IPC 发送逻辑
// -----------------------------------------------------------------------------
static int connect_and_send(const char* name) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOGE("[IPC] socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // 目标 Socket 路径
    const char* socket_path = "/data/Namespace-Proxy/ipc.sock";
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    LOGD("[IPC] Connecting to %s for package: %s", socket_path, name);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // 连接失败通常是因为接收端没启动，或者权限不足
        LOGW("[IPC] connect() failed: %s. (Is the proxy server running?)", strerror(errno));
        close(sockfd);
        return -1;
    }

    char buffer[256];
    // 格式化发送内容： 包名 PID
    int len = snprintf(buffer, sizeof(buffer), "%s %d", name, getpid());
    if (len > 0) {
        ssize_t sent = write(sockfd, buffer, len);
        if (sent > 0) {
            LOGI("[IPC] Success! Sent: '%s'", buffer);
        } else {
            LOGE("[IPC] write() failed: %s", strerror(errno));
        }
    }

    close(sockfd);
    return 0;
}

// -----------------------------------------------------------------------------
// Zygisk V4 Module Implementation
// -----------------------------------------------------------------------------

class NamespaceProxyModule : public zygisk::ModuleBase {
public:
    // onLoad 在模块加载到目标进程时立即调用
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        // 打印一条日志证明模块被 Zygisk 框架加载了
        LOGD("onLoad: Module loaded into process PID=%d", getpid());
    }

    // preAppSpecialize 在进程被 fork 出来但尚未应用沙盒限制时调用 (具有 root 权限)
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        LOGD("preAppSpecialize: Applying hide options...");
        
        // 1. 强制卸载挂载点 (解决文件检测)
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        // 2. 任务完成后自动卸载库 (解决内存检测)
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    // postAppSpecialize 在进程沙盒化完成后调用 (应用权限)
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 1. 尝试获取准确的 Java 包名
        const char* process_name = nullptr;
        bool need_release = false;

        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            need_release = true;
        }

        // 如果获取不到 Java 包名，降级使用系统进程名
        if (process_name == nullptr) {
            process_name = getprogname();
        }

        if (process_name == nullptr) {
            process_name = "unknown_process";
        }

        // 2. 过滤逻辑：跳过 Zygote 和 app_process
        // 注意：这里只是为了避免向 Zygote 发送请求，Zygisk 本身已经注入进来了
        if (strstr(process_name, "zygote") != nullptr || 
            strcmp(process_name, "app_process") == 0 || 
            strcmp(process_name, "app_process64") == 0) {
            
            LOGD("postAppSpecialize: Skipping system process: %s", process_name);
            
            // 别忘了释放 JNI 字符串
            if (need_release && args->nice_name) {
                env->ReleaseStringUTFChars(args->nice_name, process_name);
            }
            return; 
        }

        LOGI("postAppSpecialize: Target found: %s (PID: %d)", process_name, getpid());

        // 3. 发送 IPC
        connect_and_send(process_name);

        // 4. 清理 JNI 资源
        if (need_release && args->nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }

        // 函数返回后，由于设置了 DLCLOSE_MODULE_LIBRARY，模块将从内存中自动卸载
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// 注册 Zygisk 模块
REGISTER_ZYGISK_MODULE(NamespaceProxyModule)