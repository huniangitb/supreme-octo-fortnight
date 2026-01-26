#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
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
#include <algorithm>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

// ==========================================
// 数据结构与辅助函数
// ==========================================

struct RedirectRule {
    std::string source;
    std::string target;
};

// 规则列表及其互斥锁
static std::vector<RedirectRule> g_rules;
static std::mutex g_rules_mutex;
static thread_local bool g_is_hooking = false;
static bool g_hooks_installed = false;

// 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags);
static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags);
static int (*orig_access)(const char *pathname, int mode);
static int (*orig_stat)(const char *pathname, struct stat *buf);
static int (*orig_lstat)(const char *pathname, struct stat *buf);
struct linux_dirent64 { uint64_t d_ino; int64_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

// 标准化路径：去除末尾斜杠
static std::string normalize_path(const char* p) {
    if (!p) return "";
    std::string s(p);
    while (s.length() > 1 && s.back() == '/') s.pop_back();
    return s;
}

// 检查是否为媒体核心进程
static bool is_target_media_process(const char* name) {
    if (!name) return false;
    const char* media_processes[] = {
        "com.android.providers.media",
        "android.process.media",
        "com.google.android.providers.media",
        "com.android.providers.media.module"
    };
    for (const char* proc : media_processes) {
        if (strstr(name, proc)) return true;
    }
    return false;
}

// 解析规则字符串
static void parse_rules_string(const char* raw_data) {
    if (!raw_data || strncmp(raw_data, "SET_RULES:", 10) != 0) return;
    
    std::vector<RedirectRule> new_rules;
    std::string data(raw_data + 10); // 跳过 "SET_RULES:"
    
    size_t start = 0;
    size_t end = data.find(',');
    
    while (end != std::string::npos) {
        std::string part = data.substr(start, end - start);
        size_t sep = part.find('|');
        if (sep != std::string::npos) {
            RedirectRule r;
            r.source = normalize_path(part.substr(0, sep).c_str());
            r.target = normalize_path(part.substr(sep + 1).c_str());
            if (!r.source.empty()) new_rules.push_back(r);
        }
        start = end + 1;
        end = data.find(',', start);
    }
    // 处理最后一个
    std::string part = data.substr(start);
    size_t sep = part.find('|');
    if (sep != std::string::npos) {
        RedirectRule r;
        r.source = normalize_path(part.substr(0, sep).c_str());
        r.target = normalize_path(part.substr(sep + 1).c_str());
        if (!r.source.empty()) new_rules.push_back(r);
    }

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    g_rules = std::move(new_rules);
    LOGD("规则库已更新，当前规则数: %zu", g_rules.size());
}

// 获取重定向路径 (需自行 free)
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return nullptr;
    // 简单优化：非 /storage 开头直接跳过，提高性能
    if (strncmp(pathname, "/storage", 8) != 0) return nullptr;

    std::string current = normalize_path(pathname);
    std::lock_guard<std::mutex> lock(g_rules_mutex);
    
    for (const auto& rule : g_rules) {
        // 精确匹配
        if (current == rule.source) {
            return strdup(rule.target.c_str());
        }
        // 前缀匹配 (目录内文件)
        std::string prefix = rule.source + "/";
        if (current.compare(0, prefix.length(), prefix) == 0) {
            std::string redirected = rule.target + current.substr(rule.source.length());
            return strdup(redirected.c_str());
        }
    }
    return nullptr;
}

// ==========================================
// Hook 实现
// ==========================================

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, mode_t); va_end(ap);
    }
    if (g_is_hooking) return orig_openat(dirfd, pathname, flags, mode);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_openat(dirfd, r_path ? r_path : pathname, flags, mode);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_fstatat(dirfd, r_path ? r_path : pathname, buf, flags);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_mkdirat(dirfd, r_path ? r_path : pathname, mode);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (g_is_hooking) return orig_faccessat(dirfd, pathname, mode, flags);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_faccessat(dirfd, r_path ? r_path : pathname, mode, flags);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_access(const char *pathname, int mode) {
    if (g_is_hooking) return orig_access(pathname, mode);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_access(r_path ? r_path : pathname, mode);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_stat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_stat(pathname, buf);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_stat(r_path ? r_path : pathname, buf);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_lstat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_lstat(pathname, buf);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_lstat(r_path ? r_path : pathname, buf);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0 || g_is_hooking) return nread;

    char path[PATH_MAX];
    char procfd[64]; snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(procfd, path, sizeof(path) - 1);
    if (len <= 0) return nread;
    path[len] = '\0';

    if (strncmp(path, "/storage", 8) != 0) return nread;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    g_is_hooking = true;
    std::string current_dir = normalize_path(path);
    
    int bpos = 0;
    while (bpos < nread) {
        struct linux_dirent64 *d = (struct linux_dirent64 *) ((char *)dirp + bpos);
        bool hide = false;
        for (const auto& rule : g_rules) {
             size_t last_slash = rule.source.find_last_of('/');
             if (last_slash != std::string::npos) {
                 if (rule.source.substr(0, last_slash) == current_dir && 
                     rule.source.substr(last_slash + 1) == d->d_name) {
                     hide = true; break;
                 }
             }
        }
        if (hide) {
            int rest = nread - (bpos + d->d_reclen);
            if (rest > 0) memmove((char *)d, (char *)d + d->d_reclen, rest);
            nread -= d->d_reclen;
        } else {
            bpos += d->d_reclen;
        }
    }
    g_is_hooking = false;
    return nread;
}

// ==========================================
// Companion 逻辑 (Root 权限)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) { close(client_fd); return; }
    buf[len] = '\0';

    char pkg_name[256];
    int pid = 0;
    // 协议：REQ <pkg> <pid>
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        close(client_fd); return;
    }

    // 1. 上报给 Injector (关键：阻塞等待后端处理完成)
    int injector_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (injector_fd >= 0) {
        // 设置 1.5秒超时 (覆盖 App 侧的 1s 超时)
        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(injector_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(injector_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(injector_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report_msg[512];
            snprintf(report_msg, sizeof(report_msg), "REPORT %s %d", pkg_name, pid);
            if (write(injector_fd, report_msg, strlen(report_msg)) > 0) {
                char resp[32];
                // 阻塞读取，直到 Injector 返回 "OK"，意味着挂载已完成
                read(injector_fd, resp, sizeof(resp)); 
            }
        }
        close(injector_fd);
    }

    // 2. 读取规则文件
    std::string rules_content = "EMPTY";
    int file_fd = open(RULES_FILE_PATH, O_RDONLY);
    if (file_fd >= 0) {
        char file_buf[8192];
        ssize_t n = read(file_fd, file_buf, sizeof(file_buf) - 1);
        if (n > 0) {
            file_buf[n] = '\0';
            rules_content = file_buf;
        }
        close(file_fd);
    }

    // 3. 将规则返回给 App
    write(client_fd, rules_content.c_str(), rules_content.length());
    close(client_fd);
}

// ==========================================
// Zygisk Module 逻辑 (App 进程)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { this->api = api; this->env = env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* proc_raw = nullptr;
        if (args->nice_name) proc_raw = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string proc_name = proc_raw ? proc_raw : "unknown";
        if (proc_raw) env->ReleaseStringUTFChars(args->nice_name, proc_raw);

        this->pkg_name = proc_name;
        this->my_pid = getpid();
        
        // [关键修正]
        // 无论是否为媒体进程，都执行同步上报。
        // 这确保了在 injector.conf 中配置的非媒体应用（如游戏）也能获得瞬时注入（Mount/FUSE），
        // 否则它们需要等待后台轮询（最多10秒延迟）。
        fetch_rules_sync(1000); 

        // 仅对媒体进程启用 Hook 逻辑
        if (is_target_media_process(proc_name.c_str())) {
            should_hook = true;
        } else {
            should_hook = false;
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!should_hook) {
            // 对非媒体进程，彻底卸载模块，不留内存痕迹
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        install_hooks();

        // 启动热加载线程
        std::thread t([this](){
            while (true) {
                sleep(5); 
                this->fetch_rules_sync(500); 
            }
        });
        t.detach();
        
        LOGD("[%s] Media Shield 激活", pkg_name.c_str());
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    bool should_hook = false;
    std::string pkg_name;
    int my_pid;

    void fetch_rules_sync(int timeout_ms) {
        int fd = api->connectCompanion();
        if (fd < 0) return;

        char req[512];
        snprintf(req, sizeof(req), "REQ %s %d", pkg_name.c_str(), my_pid);
        write(fd, req, strlen(req));

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, timeout_ms);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                // 即使是非媒体进程收到了规则，因为 should_hook=false，稍后也会被清理，无副作用
                parse_rules_string(buf);
            }
        }
        close(fd);
    }

    void install_hooks() {
        if (g_hooks_installed) return;
        void *h = dlopen("libc.so", RTLD_NOW);
        if (!h) return;

        #define DO_HOOK(name) \
            void* s_##name = dlsym(h, #name); \
            if (s_##name) DobbyHook(s_##name, (void*)fake_##name, (void**)&orig_##name);

        DO_HOOK(openat); 
        DO_HOOK(mkdirat); 
        DO_HOOK(faccessat); 
        DO_HOOK(fstatat);
        DO_HOOK(access); 
        DO_HOOK(stat); 
        DO_HOOK(lstat);
        DO_HOOK(getdents64);

        dlclose(h);
        g_hooks_installed = true;
    }
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)