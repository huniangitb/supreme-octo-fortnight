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
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

struct RedirectRule {
    std::string source;
    std::string target;
    std::string source_name;
};

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

struct linux_dirent64 { 
    uint64_t d_ino; 
    int64_t d_off; 
    unsigned short d_reclen; 
    unsigned char d_type; 
    char d_name[]; 
};
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

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
        "com.google.android.providers.media"
    };
    for (const char* proc : media_processes) {
        if (strstr(name, proc)) return true;
    }
    return false;
}

static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return nullptr;
    std::string current = normalize_path(pathname);
    if (current.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(g_rules_mutex);
    for (const auto& rule : g_rules) {
        if (current == rule.source) return strdup(rule.target.c_str());
        std::string prefix = rule.source + "/";
        if (current.compare(0, prefix.length(), prefix) == 0) {
            std::string redirected = rule.target + current.substr(rule.source.length());
            return strdup(redirected.c_str());
        }
    }
    return nullptr;
}

// Hook 实现
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

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    g_is_hooking = true;
    char* r_path = get_redirected_path(pathname);
    int res = orig_fstatat(dirfd, r_path ? r_path : pathname, buf, flags);
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
                if (rule.source.substr(0, last_slash) == current_dir && rule.source_name == d->d_name) {
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

static void load_rules() {
    FILE* fp = fopen(RULES_FILE_PATH, "r");
    if (!fp) return;
    char line[8192];
    if (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n\r")] = '\0';
        if (strncmp(line, "SET_RULES:", 10) == 0) {
            std::lock_guard<std::mutex> lock(g_rules_mutex);
            g_rules.clear();
            char* data = strdup(line + 10);
            char* token = strtok(data, ",");
            while (token) {
                char* sep = strchr(token, '|');
                if (sep) {
                    *sep = '\0';
                    RedirectRule r;
                    r.source = normalize_path(token);
                    r.target = normalize_path(sep + 1);
                    size_t last_slash = r.source.find_last_of('/');
                    r.source_name = (last_slash != std::string::npos) ? r.source.substr(last_slash + 1) : r.source;
                    if (!r.source.empty()) g_rules.push_back(r);
                }
                token = strtok(nullptr, ",");
            }
            free(data);
        }
    }
    fclose(fp);
}

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) { close(client_fd); return; }
    buf[len] = '\0';

    int injector_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (injector_fd < 0) { write(client_fd, "ERR", 3); close(client_fd); return; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(injector_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        write(client_fd, "ERR", 3);
    } else {
        write(injector_fd, buf, len);
        char resp[64] = {0};
        ssize_t r_len = read(injector_fd, resp, sizeof(resp) - 1);
        if (r_len > 0) write(client_fd, resp, r_len);
        else write(client_fd, "ERR", 3);
    }
    close(injector_fd);
    close(client_fd);
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { this->api = api; this->env = env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        this->companion_fd = api->connectCompanion();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        const char* proc_raw = nullptr;
        if (args->nice_name) proc_raw = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string proc_name = proc_raw ? proc_raw : "unknown";
        if (proc_raw) env->ReleaseStringUTFChars(args->nice_name, proc_raw);

        if (companion_fd >= 0) {
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d", proc_name.c_str(), getpid());
            if (write(companion_fd, report, strlen(report)) > 0) {
                char buf[32]; read(companion_fd, buf, sizeof(buf));
            }
            close(companion_fd);
        }

        if (is_target_media_process(proc_name.c_str())) {
            load_rules();
            if (!g_rules.empty()) install_hooks();
        } else {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void install_hooks() {
        if (g_hooks_installed) return;
        void *h = dlopen("libc.so", RTLD_NOW);
        if (!h) return;

        #define DO_HOOK(name) \
            void* s_##name = dlsym(h, #name); \
            if (s_##name) DobbyHook(s_##name, (void*)fake_##name, (void**)&orig_##name);

        DO_HOOK(openat); DO_HOOK(mkdirat); DO_HOOK(faccessat); DO_HOOK(fstatat);
        DO_HOOK(access); DO_HOOK(stat); DO_HOOK(lstat); DO_HOOK(getdents64);

        dlclose(h);
        g_hooks_installed = true;
        LOGI("Media Shield 激活: %zu 规则", g_rules.size());
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
    int companion_fd = -1;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)