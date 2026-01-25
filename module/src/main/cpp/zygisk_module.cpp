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

// ==================== 规则解析与更新 ====================
static void load_rules_from_file() {
    FILE* fp = fopen(RULES_FILE_PATH, "r");
    if (!fp) {
        LOGE("[Rules] 无法打开规则文件: %s", RULES_FILE_PATH);
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    g_rules.clear();
    
    char line[1024];
    int rule_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "SET_RULES:", 10) == 0) {
            char* data = line + 10;
            size_t data_len = strlen(data);
            
            // 移除末尾的换行符
            if (data_len > 0 && data[data_len - 1] == '\n') {
                data[data_len - 1] = '\0';
                data_len--;
            }
            
            if (data_len == 0) continue;
            
            std::string s(data);
            size_t pos = 0, next;
            
            while ((next = s.find(',', pos)) != std::string::npos || pos < s.length()) {
                std::string pair = s.substr(pos, (next == std::string::npos) ? std::string::npos : next - pos);
                size_t sep = pair.find('|');
                
                if (sep != std::string::npos) {
                    RedirectRule rule;
                    rule.source = normalize_path(pair.substr(0, sep).c_str());
                    rule.target = normalize_path(pair.substr(sep + 1).c_str());
                    
                    size_t last_slash = rule.source.find_last_of('/');
                    if (last_slash != std::string::npos) {
                        rule.source_name = rule.source.substr(last_slash + 1);
                    } else {
                        rule.source_name = rule.source;
                    }
                    
                    if (!rule.source.empty() && !rule.target.empty()) {
                        g_rules.push_back(rule);
                        rule_count++;
                    }
                }
                
                if (next == std::string::npos) break;
                pos = next + 1;
            }
            
            break; // 只处理第一行
        }
    }
    
    fclose(fp);
    LOGI("[Rules] 从文件加载 %d 条规则", rule_count);
}

static void save_rules_to_file(const char* data) {
    if (!data) return;
    
    FILE* fp = fopen(RULES_FILE_PATH, "w");
    if (!fp) {
        LOGE("[Rules] 无法写入规则文件: %s", RULES_FILE_PATH);
        return;
    }
    
    fprintf(fp, "%s\n", data);
    fclose(fp);
    
    // 设置适当的权限
    chmod(RULES_FILE_PATH, 0644);
    LOGI("[Rules] 规则已保存到文件: %s", RULES_FILE_PATH);
}

static void rules_monitor_thread() {
    time_t last_mtime = 0;
    struct stat st;
    
    while (!g_module_should_unload) {
        // 每10秒检查一次规则文件更新
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        if (stat(RULES_FILE_PATH, &st) == 0) {
            if (st.st_mtime != last_mtime) {
                last_mtime = st.st_mtime;
                LOGI("[Rules] 检测到规则文件更新，重新加载规则");
                load_rules_from_file();
            }
        }
    }
}

// ==================== Hook 安装 ====================
static void install_media_shields() {
    if (g_hooks_installed) {
        LOGI("[Shield] Hook 已安装，跳过");
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_rules_mutex);
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

static void uninstall_hooks() {
    if (!g_hooks_installed) return;
    
    // 注意：DobbyHook 目前没有提供简单的unhook所有函数的方法
    // 这里我们只是标记卸载状态
    g_hooks_installed = false;
    LOGI("[Shield] Hook已卸载");
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
    
    if (access(LOCK_FILE_PATH, F_OK) != 0) { 
        LOGI("[Companion] injector 未运行，返回空规则");
        const char* empty_rules = "SET_RULES:";
        write(client_fd, empty_rules, strlen(empty_rules));
        close(client_fd); 
        return; 
    }

    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (target_fd < 0) {
        LOGE("[Companion] 创建socket失败: %s", strerror(errno));
        const char* error = "SET_RULES:";
        write(client_fd, error, strlen(error));
        close(client_fd);
        return;
    }
    
    struct timeval tv = {2, 0};
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
    
    char rule_data[8192] = {0};
    ssize_t received = read(target_fd, rule_data, sizeof(rule_data) - 1);
    
    close(target_fd);
    
    if (received > 0) {
        rule_data[received] = '\0';
        LOGI("[Companion] 收到规则: %d 字节", (int)received);
        
        // 保存规则到文件，供其他媒体进程使用
        save_rules_to_file(rule_data);
        
        // 发送规则数据回模块
        write(client_fd, rule_data, received);
    } else {
        LOGI("[Companion] 未收到规则数据，返回空规则");
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
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", process_name, pid);
            
            LOGI("[Module] 发送上报: %s", report);
            ssize_t sent = write(companion_fd, report, strlen(report));
            
            if (sent > 0) {
                if (this->is_media_process) {
                    LOGI("[Module] 目标媒体存储进程，接收规则并安装Hook...");
                    
                    char rule_data[8192] = {0};
                    struct timeval tv = {1, 500000};
                    setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    
                    ssize_t received = read(companion_fd, rule_data, sizeof(rule_data) - 1);
                    
                    if (received > 10) {
                        rule_data[received] = '\0';
                        LOGI("[Module] 收到规则数据: %zd 字节", received);
                        
                        // 保存规则到文件
                        save_rules_to_file(rule_data);
                        
                        // 从文件加载规则（确保一致性）
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
                        LOGI("[Module] 未收到规则或规则为空，尝试从文件加载");
                        load_rules_from_file();
                        
                        if (!g_rules.empty()) {
                            install_media_shields();
                            
                            if (!g_rules_monitor_thread.joinable()) {
                                g_module_should_unload = false;
                                g_rules_monitor_thread = std::thread(rules_monitor_thread);
                                LOGI("[Module] 规则监控线程已启动");
                            }
                            
                            LOGI("[Module] 从文件加载规则并安装Hook，保持模块加载");
                        } else {
                            LOGI("[Module] 无规则可用，卸载模块");
                            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                            this->should_unload = true;
                        }
                    }
                } else {
                    // 非媒体存储进程：上报后立即卸载模块
                    LOGI("[Module] 非媒体存储进程，上报后立即卸载模块");
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                    this->should_unload = true;
                }
            } else {
                LOGE("[Module] 上报发送失败");
                api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                this->should_unload = true;
            }
            
            close(companion_fd);
        } else {
            LOGI("[Module] 无 Companion 连接，卸载模块");
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            this->should_unload = true;
        }
        
        if (args->nice_name && process_name) {
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
        
        LOGI("[Module] 处理完成");
    }
    
    ~AppReporterModule() {
        // 模块卸载前的清理工作
        if (this->should_unload) {
            g_module_should_unload = true;
            
            if (g_rules_monitor_thread.joinable()) {
                g_rules_monitor_thread.join();
                LOGI("[Module] 规则监控线程已停止");
            }
            
            uninstall_hooks();
            
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