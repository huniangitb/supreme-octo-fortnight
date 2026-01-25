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
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* TARGET_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* LOCK_FILE_PATH = "/data/Namespace-Proxy/app.lock";

struct RedirectRule {
    std::string source;
    std::string target;
    std::string source_name; // 仅文件名，用于 getdents 过滤
};

static std::vector<RedirectRule> g_rules;
static thread_local bool g_is_hooking = false;

// 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags);
static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags);
struct linux_dirent64 { uint64_t d_ino; int64_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

// 路径工具：去掉末尾斜杠
static std::string normalize_path(const char* p) {
    if (!p) return "";
    std::string s(p);
    while (s.length() > 1 && s.back() == '/') s.pop_back();
    return s;
}

// 核心重定向逻辑
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return nullptr;
    std::string current = normalize_path(pathname);

    for (const auto& rule : g_rules) {
        if (current == rule.source) return strdup(rule.target.c_str());
        
        // 子路径匹配
        std::string prefix = rule.source + "/";
        if (current.compare(0, prefix.length(), prefix) == 0) {
            std::string sub = current.substr(rule.source.length());
            return strdup((rule.target + sub).c_str());
        }
    }
    return nullptr;
}

// --- Hooks ---

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = 0; if (flags & O_CREAT) mode = va_arg(ap, mode_t);
    va_end(ap);
    if (g_is_hooking) return (flags & O_CREAT) ? orig_openat(dirfd, pathname, flags, mode) : orig_openat(dirfd, pathname, flags);

    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = (flags & O_CREAT) ? orig_openat(dirfd, r_path ? r_path : pathname, flags, mode) : orig_openat(dirfd, r_path ? r_path : pathname, flags);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_mkdirat(dirfd, r_path ? r_path : pathname, mode);
    if (r_path) { LOGI("[Virtual] Redir mkdirat -> %s", r_path); free(r_path); }
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

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_fstatat(dirfd, r_path ? r_path : pathname, buf, flags);
    if (r_path) free(r_path);
    g_is_hooking = false;
    return res;
}

static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0 || g_is_hooking || g_rules.empty()) return nread;

    g_is_hooking = true;
    char path[PATH_MAX];
    char procfd[64]; snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    
    if (readlink(procfd, path, PATH_MAX) > 0) {
        std::string current_dir = normalize_path(path);
        for (int bpos = 0; bpos < nread; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) ((char *)dirp + bpos);
            bool hide = false;
            
            for (const auto& rule : g_rules) {
                // 如果当前目录是规则源路径的父目录，且文件名匹配
                size_t last_slash = rule.source.find_last_of('/');
                if (last_slash != std::string::npos) {
                    std::string parent = rule.source.substr(0, last_slash);
                    if (parent == current_dir && rule.source_name == d->d_name) {
                        hide = true; break;
                    }
                }
            }

            if (hide) {
                int rest = nread - (bpos + d->d_reclen);
                if (rest > 0) memmove(d, (char *)d + d->d_reclen, rest);
                nread -= d->d_reclen;
                continue;
            }
            bpos += d->d_reclen;
        }
    }
    g_is_hooking = false;
    return nread;
}

// 解析后端发来的规则
static void parse_rules(const char* data) {
    if (strncmp(data, "SET_RULES:", 10) != 0) return;
    g_rules.clear();
    std::string s(data + 10);
    size_t pos = 0, next;
    while ((next = s.find(',', pos)) != std::string::npos || pos < s.length()) {
        std::string pair = s.substr(pos, (next == std::string::npos) ? std::string::npos : next - pos);
        size_t sep = pair.find('|');
        if (sep != std::string::npos) {
            RedirectRule rule;
            rule.source = normalize_path(pair.substr(0, sep).c_str());
            rule.target = normalize_path(pair.substr(sep + 1).c_str());
            size_t last_s = rule.source.find_last_of('/');
            rule.source_name = (last_s != std::string::npos) ? rule.source.substr(last_s + 1) : rule.source;
            g_rules.push_back(rule);
            LOGI("[Rules] Added Rule: %s -> %s", rule.source.c_str(), rule.target.c_str());
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
}

// --- Zygisk 基础 ---

static void companion_handler(int client_fd) {
    char buf[256];
    if (read(client_fd, buf, sizeof(buf)-1) <= 0) { close(client_fd); return; }
    
    if (access(LOCK_FILE_PATH, F_OK) != 0) { write(client_fd, "ERR_LOCK", 8); close(client_fd); return; }

    int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);

    if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        write(target_fd, buf, strlen(buf));
        char resp[8192] = {0};
        struct timeval tv = {2, 0};
        setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (read(target_fd, resp, sizeof(resp)-1) > 0) {
            write(client_fd, resp, strlen(resp)); // 把 SET_RULES 传回模块
        }
    }
    close(target_fd); close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { this->api = api; this->env = env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->uid < 10000) { this->companion_fd = -1; return; }
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* process_name = nullptr;
        if (args->nice_name) process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name) process_name = "unknown";
        
        if (companion_fd >= 0) {
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d STATUS:HOOKED", process_name, getpid());
            write(companion_fd, report, strlen(report));
            
            char rule_data[8192] = {0};
            struct timeval tv = {1, 500000};
            setsockopt(companion_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (read(companion_fd, rule_data, sizeof(rule_data)-1) > 0) {
                parse_rules(rule_data);
            }
            close(companion_fd);
        }

        bool is_media = (strstr(process_name, "com.android.providers.media") || strstr(process_name, "android.process.media"));
        if (is_media && !g_rules.empty()) {
            LOGI("System Media Process Detected. Installing Shield.");
            void *h = dlopen("libc.so", RTLD_NOW);
            #define HOOK(n) void* p_##n = dlsym(h, #n); if(p_##n) DobbyHook(p_##n, (dobby_dummy_func_t)fake_##n, (dobby_dummy_func_t*)&orig_##n)
            HOOK(openat); HOOK(mkdirat); HOOK(faccessat); HOOK(fstatat); HOOK(getdents64);
            dlclose(h);
        }
        if (args->nice_name && process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
    }
private:
    zygisk::Api *api; JNIEnv *env; int companion_fd;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)