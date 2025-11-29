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

#define LOG_TAG "Zygisk_IPC"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// 获取进程名的系统函数声明
extern "C" const char* getprogname();

// -----------------------------------------------------------------------------
// IPC 发送逻辑 (保持不变)
// -----------------------------------------------------------------------------
static int connect_and_send(const char* name) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOGE("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // 确保这个路径与你的服务端监听路径一致
    strncpy(addr.sun_path, "/data/Namespace-Proxy/ipc.sock", sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // 连接失败通常是因为接收端没启动，视为 Debug 信息
        LOGD("connect() failed (Injector might be offline): %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer), "%s %d", name, getpid());
    if (len > 0) {
        write(sockfd, buffer, len);
        LOGD("IPC Sent: %s", buffer);
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
    }

    // preAppSpecialize 在进程被 fork 出来但尚未应用沙盒限制时调用 (具有 root 权限)
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // [实现隐藏的核心部分]
        
        // 1. FORCE_DENYLIST_UNMOUNT:
        // 强制对此进程执行 Magisk/KernelSU 的“排除列表”卸载逻辑。
        // 无论用户是否将该应用添加到排除列表，都会移除模块的文件挂载。
        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        // 2. DLCLOSE_MODULE_LIBRARY:
        // 在 postAppSpecialize 执行完毕后，自动 dlclose 本模块的 .so 文件。
        // 这会清除内存映射 (/proc/self/maps) 中的模块痕迹。
        // 注意：启用此项后，不能在 post 阶段之后保留任何 Hook (如 PLT Hook 或 Native Hook)。
        // 由于本模块只发一次 IPC，不需要持久驻留，所以这是最佳隐藏方案。
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    // postAppSpecialize 在进程沙盒化完成后调用 (应用权限)
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // 1. 获取当前进程名
        const char* name = getprogname();
        
        // 2. 过滤掉 zygote 自身和 app_process
        if (name == nullptr || strstr(name, "zygote") != nullptr || strcmp(name, "app_process") == 0) {
            return; 
        }

        // 3. (可选) 你也可以使用 args->nice_name 获取包名，这比 getprogname 更准确
        // 但为了兼容你原有的逻辑，这里保留 getprogname，或者两者结合
        const char* final_name = name;
        if (args->nice_name) {
            // 将 jstring 转换为 C string (简单示例，未处理释放)
            // const char* nice_name_c = env->GetStringUTFChars(args->nice_name, nullptr);
            // final_name = nice_name_c;
            // (注意：如果在 DLCLOSE 模式下，尽量减少复杂的 JNI 操作，直接用 getprogname 足够简单有效)
        }

        LOGD("Module specialized in: %s (PID: %d)", final_name, getpid());

        // 4. 发送 IPC
        connect_and_send(final_name);

        // 函数返回后，由于设置了 DLCLOSE_MODULE_LIBRARY，模块将从内存中消失
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

// 注册 Zygisk 模块 (V4 API 使用相同的宏)
REGISTER_ZYGISK_MODULE(NamespaceProxyModule)