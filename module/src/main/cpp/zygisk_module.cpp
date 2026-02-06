#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <sys/system_properties.h>
#include <vector> // 引入 vector 方便管理黑名单
#include <string> // 引入 string

#include "zygisk.hpp"

// ... (前面的 Rules 配置和 hook 函数保持不变) ...

// ============================================================================
// 4. Zygisk 模块主体
// ============================================================================

class PropModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        // 绝对不要开启 DLCLOSE，否则安全库延迟调用时必崩
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) return;
        hookAllLoadedModules();
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override { }

private:
    zygisk::Api *api;
    JNIEnv *env;

    // 检查路径是否在黑名单中
    bool is_ignored_lib(const char* path) {
        // 【关键黑名单】
        // 这些库绝对不能 Hook，否则会崩溃或死锁
        static const char* IGNORE_LIST[] = {
            "libc.so",              // 自身
            "zygisk",               // 模块自身
            "libnativebridge.so",   // 系统桥接库 (崩溃日志中出现)
            "libdl.so",             // 动态链接器
            "libm.so",              // 数学库
            "liblog.so",            // 日志库
            
            // 【风控/反作弊库】(根据崩溃日志添加)
            "libmetasec_ml.so",     // 字节系风控
            "libmsao.so",           // 另一常见的风控
            "libixia.so",           // 阿里系/加固
            "libjiagu.so",          // 360加固
            "libnesec.so",          // 网易易盾
            "libunwind.so"          // 栈回溯库
        };

        for (const char* item : IGNORE_LIST) {
            if (strstr(path, item) != NULL) {
                return true; // 在黑名单里，跳过
            }
        }
        return false;
    }

    void hookAllLoadedModules() {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp == NULL) return;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            uintptr_t start, end;
            char perms[5];
            uint64_t offset;
            uint32_t dev_major, dev_minor;
            unsigned long inode;
            char path[256];

            int fields = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64 " %x:%x %lu %s",
                                &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);

            if (fields == 8 && strstr(perms, "x") && inode != 0) {
                
                // 【核心修改】增加黑名单过滤
                if (!is_ignored_lib(path)) {
                    
                    dev_t dev = makedev(dev_major, dev_minor);

                    // 注册三个核心 Hook
                    api->pltHookRegister(dev, inode, "__system_property_get", 
                                        (void *)my_system_property_get, 
                                        (void **)&orig_system_property_get);

                    api->pltHookRegister(dev, inode, "__system_property_read", 
                                        (void *)my_system_property_read, 
                                        (void **)&orig_system_property_read);

                    api->pltHookRegister(dev, inode, "__system_property_read_callback", 
                                        (void *)my_system_property_read_callback, 
                                        (void **)&orig_system_property_read_callback);
                }
            }
        }
        fclose(fp);

        api->pltHookCommit();
    }
};

REGISTER_ZYGISK_MODULE(PropModule)