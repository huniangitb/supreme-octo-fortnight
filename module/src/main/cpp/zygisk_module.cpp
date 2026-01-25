#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/inotify.h>
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
#include <thread>
#include <mutex>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

// ==================== 数据结构 ====================
struct RedirectRule {
    std::string source;
    std::string target;
    std::string source_name;
};

static std::vector<RedirectRule> g_rules;
static std::mutex g_rules_mutex;
static thread_local bool g_is_hooking = false;
static bool g_hooks_installed = false;
static bool g_module_should_unload = false;
static int g_inotify_fd = -1;
static std::thread g_rules_monitor_thread;

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
    
    const char* media_processes[] = {
        "com.android.providers.media",
        "android.process.media",
        "media"
    };
    
    for (const char* proc : media_processes) {
        if (strstr(name, proc) != nullptr) {
            return true;
        }
    }
    return false;
}

// ==================== 路径重定向逻辑 ====================
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return nullptr;
    
    std::string current = normalize_path(pathname);
    if (current.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    for (const auto& rule : g_rules) {
        if (current == rule.source) {
            return strdup(rule.target.c_str());
        }
        
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
    if (nread <= 0 || g_is_hooking) return nread;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    if (g_rules.empty()) return nread;

    g_is_hooking = true;
    
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
            
            for (const auto& rule : g_rules) {
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
                continue;
            }
            bpos += d->d_reclen;
        }
    }
    
    g_is_hooking = false;
    return nread;
}

// ==================== 规则文件处理 ====================
static void load_rules_from_file() {
    FILE* fp = fopen(RULES_FILE_PATH, "r");
    if (!fp) {
        LOGE("[Rules] 无法打开规则文件: %s", RULES_FILE_PATH);
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    g_rules.clear();
    
    char line[8192];
    if (fgets(line, sizeof(line), fp)) {
        // 移除换行符
        line[strcspn(line, "\n\r")] = '\0';
        
        // 检查是否是SET_RULES:开头
        if (strncmp(line, "SET_RULES:", 10) == 0) {
            char* data = line + 10;
            
            // 如果只有SET_RULES:，没有内容，清空规则
            if (strlen(data) == 0) {
                LOGI("[Rules] 规则文件为空，清空规则");
                g_rules.clear();
                fclose(fp);
                return;
            }
            
            int rule_count = 0;
            char* token = strtok(data, ",");
            while (token != nullptr) {
                char* sep = strchr(token, '|');
                if (sep != nullptr) {
                    RedirectRule rule;
                    *sep = '\0';
                    rule.source = normalize_path(token);
                    rule.target = normalize_path(sep + 1);
                    
                    size_t last_slash = rule.source.find_last_of('/');
                    if (last_slash != std::string::npos) {
                        rule.source_name = rule.source.substr(last_slash + 1);
                    } else {
                        rule.source_name = rule.source;
                    }
                    
                    if (!rule.source.empty() && !rule.target.empty()) {
                        g_rules.push_back(rule);
                        rule_count++;
                        LOGI("[Rules] 加载规则 %d: %s -> %s", rule_count, rule.source.c_str(), rule.target.c_str());
                    }
                }
                token = strtok(nullptr, ",");
            }
            
            LOGI("[Rules] 从文件加载 %d 条规则", rule_count);
        } else {
            LOGE("[Rules] 规则文件格式错误");
        }
    } else {
        LOGI("[Rules] 规则文件为空");
    }
    
    fclose(fp);
}

static void rules_monitor_thread() {
    g_inotify_fd = inotify_init();
    if (g_inotify_fd < 0) {
        LOGE("[Rules] 无法初始化inotify");
        return;
    }
    
    int wd = inotify_add_watch(g_inotify_fd, RULES_FILE_PATH, IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        LOGE("[Rules] 无法监控规则文件");
        close(g_inotify_fd);
        return;
    }
    
    LOGI("[Rules] 开始监控规则文件: %s", RULES_FILE_PATH);
    
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    
    while (!g_module_should_unload) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_inotify_fd, &fds);
        
        struct timeval tv = {5, 0}; // 5秒超时
        
        int ret = select(g_inotify_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (ret == 0) {
            // 超时，检查文件是否存在
            if (access(RULES_FILE_PATH, F_OK) != 0) {
                // 文件被删除，清空规则
                std::lock_guard<std::mutex> lock(g_rules_mutex);
                g_rules.clear();
                LOGI("[Rules] 规则文件被删除，清空规则");
            }
            continue;
        }
        
        if (!FD_ISSET(g_inotify_fd, &fds)) continue;
        
        ssize_t len = read(g_inotify_fd, buf, sizeof(buf));
        if (len <= 0) continue;
        
        for (char *ptr = buf; ptr < buf + len; ) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            ptr += sizeof(struct inotify_event) + ev->len;
            
            if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                LOGI("[Rules] 检测到规则文件更新，重新加载规则");
                load_rules_from_file();
            }
        }
    }
    
    inotify_rm_watch(g_inotify_fd, wd);
    close(g_inotify_fd);
    LOGI("[Rules] 停止监控规则文件");
}

// ==================== Hook 安装 ====================
static void install_media_shields() {
    if (g_hooks_installed) {
        LOGI("[Shield] Hook 已安装，跳过");
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    if (g_rules.empty()) {
        LOGI("[Shield] 无规则可用，不安装Hook");
        return;
    }
    
    LOGI("[Shield] 安装Dobby Hook... 规则数量: %zu", g_rules.size());
    
    void *libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) {
        LOGE("[Shield] 无法加载 libc.so");
        return;
    }
    
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
    
    LOGI("[Shield] Dobby Hook已激活");
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
    
    LOGI("[Companion] 收到上报: %s", buf);
    
    // 简单的回复，表示上报已收到
    const char* response = "OK";
    write(client_fd, response, strlen(response));
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
        if (args->uid < 10000) { 
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            this->companion_fd = -1;
            this->is_media_process = false;
            return; 
        }
        
        this->companion_fd = api->connectCompanion();
        LOGI("[Module] 用户应用 UID: %d, Companion FD: %d", args->uid, this->companion_fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        
        if (!process_name) {
            process_name = "unknown";
        }
        
        int pid = getpid();
        LOGI("[Module] 进程启动: %s (PID: %d, UID: %d)", process_name, pid, getuid());
        
        this->is_media_process = is_target_media_process(process_name);
        LOGI("[Module] 是否为媒体存储进程: %s", this->is_media_process ? "是" : "否");
        
        if (companion_fd >= 0) {
            // 发送上报并等待回复（阻塞应用加载）
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d", process_name, pid);
            
            LOGI("[Module] 发送上报并等待注入器完成...");
            ssize_t sent = write(companion_fd, report, strlen(report));
            
            if (sent > 0) {
                // 设置接收超时
                struct timeval tv = {5, 0}; // 5秒超时
                setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                
                char response[32] = {0};
                ssize_t received = read(companion_fd, response, sizeof(response) - 1);
                
                if (received > 0) {
                    response[received] = '\0';
                    LOGI("[Module] 收到注入器回复: %s", response);
                } else {
                    LOGI("[Module] 未收到注入器回复，继续执行");
                }
            } else {
                LOGE("[Module] 上报发送失败");
            }
            
            close(companion_fd);
        } else {
            LOGI("[Module] 无 Companion 连接");
        }
        
        // 媒体存储进程加载规则和安装Hook
        if (this->is_media_process) {
            LOGI("[Module] 媒体存储进程，从文件加载规则...");
            
            // 加载规则
            load_rules_from_file();
            
            // 安装Hook
            if (!g_rules.empty()) {
                install_media_shields();
                
                // 启动规则监控线程
                if (!g_rules_monitor_thread.joinable()) {
                    g_module_should_unload = false;
                    g_rules_monitor_thread = std::thread(rules_monitor_thread);
                    LOGI("[Module] 规则监控线程已启动");
                }
                
                LOGI("[Module] Dobby Hook 已安装，保持模块加载");
                // 不卸载模块，保持Hook生效
            } else {
                LOGI("[Module] 无有效规则，卸载模块");
                api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                this->should_unload = true;
            }
        } else {
            // 非媒体存储进程：上报后立即卸载模块
            LOGI("[Module] 非媒体存储进程，上报后立即卸载模块");
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            this->should_unload = true;
        }
        
        if (args->nice_name && process_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
        
        LOGI("[Module] 处理完成");
    }
    
    ~AppReporterModule() {
        if (this->should_unload) {
            g_module_should_unload = true;
            
            if (g_rules_monitor_thread.joinable()) {
                g_rules_monitor_thread.join();
                LOGI("[Module] 规则监控线程已停止");
            }
            
            if (g_inotify_fd >= 0) {
                close(g_inotify_fd);
                g_inotify_fd = -1;
            }
            
            std::lock_guard<std::mutex> lock(g_rules_mutex);
            g_rules.clear();
            
            LOGI("[Module] 模块资源已清理");
        }
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd = -1;
    bool is_media_process = false;
    bool should_unload = false;
};

// ==================== 模块注册 ====================
REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)