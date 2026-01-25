#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

// ==================== 数据结构 ====================
struct RedirectRule {
    std::string source;
    std::string target;
    std::string source_name; // 仅文件名，用于 getdents 过滤
};

static std::vector<RedirectRule> g_rules;
static thread_local bool g_is_hooking = false;
static bool g_hooks_installed = false;

// ==================== 原始函数指针 ====================
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags);
static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags);
static int (*orig_access)(const char *pathname, int mode);
static int (*orig_stat)(const char *pathname, struct stat *buf);
static int (*orig_lstat)(const char *pathname, struct stat *buf);

struct linux_dirent64 { 
    uint64_t d_ino; 
    int64_t d_off; 
    unsigned short d_reclen; 
    unsigned char d_type; 
    char d_name[]; 
};
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

// ==================== 工具函数 ====================
static std::string normalize_path(const char* p) {
    if (!p) return "";
    std::string s(p);
    while (s.length() > 1 && s.back() == '/') s.pop_back();
    return s;
}

static bool is_target_media_process(const char* name) {
    if (!name) return false;
    return (strstr(name, "com.android.providers.media") != nullptr || 
            strstr(name, "android.process.media") != nullptr);
}

// ==================== 路径重定向逻辑 ====================
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return nullptr;
    
    std::string current = normalize_path(pathname);
    if (current.empty()) return nullptr;

    for (const auto& rule : g_rules) {
        // 精确匹配
        if (current == rule.source) {
            return strdup(rule.target.c_str());
        }
        
        // 子路径匹配
        std::string prefix = rule.source + "/";
        if (current.compare(0, prefix.length(), prefix) == 0) {
            std::string sub = current.substr(rule.source.length());
            std::string redirected = rule.target + sub;
            return strdup(redirected.c_str());
        }
    }
    return nullptr;
}

// ==================== Hook 函数实现 ====================

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    // 避免递归调用
    if (g_is_hooking) {
        if (flags & O_CREAT) {
            va_list ap; 
            va_start(ap, flags);
            mode_t mode = va_arg(ap, mode_t);
            va_end(ap);
            return orig_openat(dirfd, pathname, flags, mode);
        }
        return orig_openat(dirfd, pathname, flags);
    }

    g_is_hooking = true;
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] openat 重定向: %s -> %s", pathname, r_path);
        if (flags & O_CREAT) {
            res = orig_openat(dirfd, r_path, flags, mode);
        } else {
            res = orig_openat(dirfd, r_path, flags);
        }
        free(r_path);
    } else {
        if (flags & O_CREAT) {
            res = orig_openat(dirfd, pathname, flags, mode);
        } else {
            res = orig_openat(dirfd, pathname, flags);
        }
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] mkdirat 重定向: %s -> %s", pathname, r_path);
        res = orig_mkdirat(dirfd, r_path, mode);
        free(r_path);
    } else {
        res = orig_mkdirat(dirfd, pathname, mode);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (g_is_hooking) return orig_faccessat(dirfd, pathname, mode, flags);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] faccessat 重定向: %s -> %s", pathname, r_path);
        res = orig_faccessat(dirfd, r_path, mode, flags);
        free(r_path);
    } else {
        res = orig_faccessat(dirfd, pathname, mode, flags);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] fstatat 重定向: %s -> %s", pathname, r_path);
        res = orig_fstatat(dirfd, r_path, buf, flags);
        free(r_path);
    } else {
        res = orig_fstatat(dirfd, pathname, buf, flags);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_access(const char *pathname, int mode) {
    if (g_is_hooking) return orig_access(pathname, mode);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] access 重定向: %s -> %s", pathname, r_path);
        res = orig_access(r_path, mode);
        free(r_path);
    } else {
        res = orig_access(pathname, mode);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_stat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_stat(pathname, buf);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] stat 重定向: %s -> %s", pathname, r_path);
        res = orig_stat(r_path, buf);
        free(r_path);
    } else {
        res = orig_stat(pathname, buf);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_lstat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_lstat(pathname, buf);
    
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res;
    
    if (r_path) {
        LOGD("[Virtual] lstat 重定向: %s -> %s", pathname, r_path);
        res = orig_lstat(r_path, buf);
        free(r_path);
    } else {
        res = orig_lstat(pathname, buf);
    }
    
    g_is_hooking = false;
    return res;
}

static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0 || g_is_hooking || g_rules.empty()) return nread;

    g_is_hooking = true;
    
    // 获取当前目录路径
    char path[PATH_MAX];
    char procfd[64]; 
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    
    ssize_t len = readlink(procfd, path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        std::string current_dir = normalize_path(path);
        
        for (int bpos = 0; bpos < nread; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) ((char *)dirp + bpos);
            bool hide = false;
            
            // 检查是否需要隐藏此条目
            for (const auto& rule : g_rules) {
                // 如果当前目录是规则源路径的父目录，且文件名匹配
                size_t last_slash = rule.source.find_last_of('/');
                if (last_slash != std::string::npos) {
                    std::string parent = rule.source.substr(0, last_slash);
                    if (parent == current_dir && rule.source_name == d->d_name) {
                        hide = true;
                        LOGD("[Virtual] getdents64 隐藏: %s/%s", current_dir.c_str(), d->d_name);
                        break;
                    }
                }
            }

            if (hide) {
                int rest = nread - (bpos + d->d_reclen);
                if (rest > 0) {
                    memmove((char *)d, (char *)d + d->d_reclen, rest);
                }
                nread -= d->d_reclen;
                // 不增加 bpos，因为条目已被移除
                continue;
            }
            bpos += d->d_reclen;
        }
    }
    
    g_is_hooking = false;
    return nread;
}

// ==================== 规则解析 ====================
static void parse_rules(const char* data) {
    if (!data) {
        LOGE("[Rules] 无规则数据");
        g_rules.clear();
        return;
    }
    
    LOGI("[Rules] 原始规则数据: %s", data);
    
    if (strncmp(data, "SET_RULES:", 10) != 0) {
        LOGE("[Rules] 无效规则格式");
        return;
    }
    
    g_rules.clear();
    std::string s(data + 10);
    LOGI("[Rules] 解析规则字符串: %s", s.c_str());
    
    size_t pos = 0, next;
    int rule_count = 0;
    
    while ((next = s.find(',', pos)) != std::string::npos || pos < s.length()) {
        std::string pair = s.substr(pos, (next == std::string::npos) ? std::string::npos : next - pos);
        size_t sep = pair.find('|');
        
        if (sep != std::string::npos) {
            RedirectRule rule;
            rule.source = normalize_path(pair.substr(0, sep).c_str());
            rule.target = normalize_path(pair.substr(sep + 1).c_str());
            
            // 提取源路径的文件名
            size_t last_slash = rule.source.find_last_of('/');
            if (last_slash != std::string::npos) {
                rule.source_name = rule.source.substr(last_slash + 1);
            } else {
                rule.source_name = rule.source;
            }
            
            if (!rule.source.empty() && !rule.target.empty()) {
                g_rules.push_back(rule);
                LOGI("[Rules] 添加规则: %s -> %s", rule.source.c_str(), rule.target.c_str());
                rule_count++;
            }
        }
        
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    
    LOGI("[Rules] 共加载 %d 条规则", rule_count);
}

// ==================== Hook 安装 ====================
static void install_media_shields() {
    if (g_hooks_installed) {
        LOGI("[Shield] Hook 已安装，跳过");
        return;
    }
    
    LOGI("[Shield] 检测到媒体中心，启动隔离保护... 规则数量: %zu", g_rules.size());
    
    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) {
        LOGE("[Shield] 无法加载 libc.so");
        return;
    }
    
    // 定义 Hook 宏
    #define HOOK_FUNC(func_name) do { \
        void* orig_sym = dlsym(libc_handle, #func_name); \
        if (orig_sym) { \
            if (DobbyHook(orig_sym, (void*)fake_##func_name, (void**)&orig_##func_name) == 0) { \
                LOGI("[Shield] Hook " #func_name " 成功"); \
            } else { \
                LOGE("[Shield] Hook " #func_name " 失败"); \
            } \
        } else { \
            LOGE("[Shield] 未找到符号 " #func_name); \
        } \
    } while(0)
    
    // 安装所有 Hook
    HOOK_FUNC(openat);
    HOOK_FUNC(mkdirat);
    HOOK_FUNC(faccessat);
    HOOK_FUNC(fstatat);
    HOOK_FUNC(access);
    HOOK_FUNC(stat);
    HOOK_FUNC(lstat);
    HOOK_FUNC(getdents64);
    
    #undef HOOK_FUNC
    
    dlclose(libc_handle);
    g_hooks_installed = true;
    
    LOGI("[Shield] 媒体保护隔离已激活");
}

// ==================== Companion 处理 ====================
static void companion_handler(int client_fd) {
    char buf[256];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) { 
        close(client_fd); 
        return; 
    }
    buf[len] = '\0';
    
    LOGI("[Companion] 收到请求: %s", buf);
    
    // 检查锁文件是否存在（injector 是否在运行）
    if (access(LOCK_FILE_PATH, F_OK) != 0) { 
        LOGI("[Companion] injector 未运行，返回空规则");
        const char* empty_rules = "SET_RULES:";
        write(client_fd, empty_rules, strlen(empty_rules));
        close(client_fd); 
        return; 
    }

    // 连接到 injector
    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        LOGE("[Companion] 创建socket失败: %s", strerror(errno));
        const char* error = "SET_RULES:";
        write(client_fd, error, strlen(error));
        close(client_fd);
        return;
    }
    
    // 设置超时
    struct timeval tv = {2, 0}; // 2秒超时
    setsockopt(target_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGI("[Companion] 无法连接到 injector: %s", strerror(errno));
        const char* error = "SET_RULES:";
        write(client_fd, error, strlen(error));
        close(target_fd);
        close(client_fd);
        return;
    }
    
    LOGI("[Companion] 连接到 injector 成功");
    
    // 发送上报消息
    ssize_t sent = write(target_fd, buf, strlen(buf));
    if (sent <= 0) {
        LOGE("[Companion] 发送失败: %s", strerror(errno));
        const char* error = "SET_RULES:";
        write(client_fd, error, strlen(error));
        close(target_fd);
        close(client_fd);
        return;
    }
    
    LOGI("[Companion] 已发送 %zd 字节", sent);
    
    // 接收规则数据
    char rule_data[8192] = {0};
    ssize_t received = read(target_fd, rule_data, sizeof(rule_data) - 1);
    
    close(target_fd);  // 关闭与 injector 的连接
    
    if (received > 0) {
        rule_data[received] = '\0';
        LOGI("[Companion] 收到规则: %d 字节", (int)received);
        // 发送规则数据回模块
        write(client_fd, rule_data, received);
    } else {
        LOGI("[Companion] 未收到规则数据，返回空规则");
        // 发送空响应
        const char* empty_rules = "SET_RULES:";
        write(client_fd, empty_rules, strlen(empty_rules));
    }
    
    close(client_fd);
    LOGI("[Companion] 处理完成");
}

// ==================== Zygisk 模块类 ====================
class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        this->api = api; 
        this->env = env;
        LOGI("[Module] 模块已加载");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 只处理用户应用 (UID >= 10000)
        if (args->uid < 10000) { 
            // 系统进程：不连接 Companion，并卸载模块
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            this->companion_fd = -1;
            return; 
        }
        
        this->companion_fd = api->connectCompanion();
        LOGI("[Module] 用户应用 UID: %d, Companion FD: %d", args->uid, this->companion_fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        
        // 获取进程名
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        
        if (!process_name) {
            process_name = "unknown";
        }
        
        int pid = getpid();
        LOGI("[Module] 进程启动: %s (PID: %d, UID: %d)", process_name, pid, getuid());
        
        if (companion_fd >= 0) {
            // 发送上报消息
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", process_name, pid);
            
            LOGI("[Module] 发送上报: %s", report);
            ssize_t sent = write(companion_fd, report, strlen(report));
            
            if (sent > 0) {
                LOGI("[Module] 上报发送成功: %zd 字节", sent);
                
                // 判断是否为媒体进程
                bool is_media = is_target_media_process(process_name);
                
                if (is_media) {
                    LOGI("[Module] 目标媒体进程，准备接收规则...");
                    
                    // 接收规则数据
                    char rule_data[8192] = {0};
                    struct timeval tv = {1, 500000}; // 1.5秒超时
                    setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    
                    ssize_t received = read(companion_fd, rule_data, sizeof(rule_data) - 1);
                    
                    if (received > 10) { // 确保不是空规则
                        rule_data[received] = '\0';
                        LOGI("[Module] 收到规则数据: %zd 字节", received);
                        
                        // 解析规则
                        parse_rules(rule_data);
                        
                        // 安装 Hook
                        if (!g_rules.empty()) {
                            install_media_shields();
                        } else {
                            LOGI("[Module] 无有效规则，不安装 Hook");
                        }
                    } else {
                        LOGI("[Module] 未收到规则或规则为空");
                    }
                } else {
                    LOGI("[Module] 非媒体进程，上报后卸载模块");
                    // 普通应用：上报后立即卸载模块，减少内存占用和检测风险
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                }
            } else {
                LOGE("[Module] 上报发送失败");
            }
            
            close(companion_fd);
        } else {
            LOGI("[Module] 无 Companion 连接");
        }
        
        // 释放字符串资源
        if (args->nice_name && process_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
        
        LOGI("[Module] 处理完成");
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd = -1;
};

// ==================== 模块注册 ====================
REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)