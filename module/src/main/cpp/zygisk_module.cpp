#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <ctype.h>

#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 必须与 Injector 保持一致
static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

// ==========================================
// 数据结构与全局变量 (纯 C)
// ==========================================

typedef struct RedirectRule {
    char* source;
    char* target;
} RedirectRule;

typedef struct RuleList {
    RedirectRule* rules;
    size_t count;
    size_t capacity;
} RuleList;

static RuleList g_rules = {0};
static pthread_mutex_t g_rules_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_hooks_installed = false;
static __thread bool g_is_hooking = false; // 防止递归 Hook

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

// ==========================================
// 辅助函数
// ==========================================

static char* normalize_path(const char* p) {
    if (!p || p[0] == '\0') {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    size_t len = strlen(p);
    while (len > 1 && p[len - 1] == '/') len--;
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    strncpy(result, p, len);
    result[len] = '\0';
    return result;
}

static bool is_target_media_process(const char* name) {
    if (!name) return false;
    const char* media_processes[] = {
        "com.android.providers.media",
        "android.process.media",
        "com.google.android.providers.media",
        "com.android.providers.media.module"
    };
    for (size_t i = 0; i < sizeof(media_processes)/sizeof(media_processes[0]); i++) {
        if (strstr(name, media_processes[i])) return true;
    }
    return false;
}

// ==========================================
// 规则解析逻辑
// ==========================================

static void clear_rule_list(RuleList* list) {
    if (list->rules) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->rules[i].source);
            free(list->rules[i].target);
        }
        free(list->rules);
    }
    list->rules = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool add_rule(RuleList* list, const char* source, const char* target) {
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        RedirectRule* new_rules = (RedirectRule*)realloc(list->rules, new_capacity * sizeof(RedirectRule));
        if (!new_rules) return false;
        list->rules = new_rules;
        list->capacity = new_capacity;
    }
    RedirectRule* rule = &list->rules[list->count++];
    rule->source = strdup(source);
    rule->target = target ? strdup(target) : NULL;
    return true;
}

static void parse_rules_string(const char* raw_data) {
    if (!raw_data || strncmp(raw_data, "SET_RULES:", 10) != 0) return;
    const char* data = raw_data + 10;
    
    RuleList new_rules = {0};
    
    const char* start = data;
    while (*start) {
        const char* end = strchr(start, ',');
        if (!end) end = start + strlen(start);
        
        char* pipe = (char*)memchr(start, '|', end - start);
        if (pipe) {
            size_t src_len = pipe - start;
            char* src = (char*)malloc(src_len + 1);
            strncpy(src, start, src_len); src[src_len] = '\0';
            
            size_t dst_len = end - (pipe + 1);
            char* dst = (char*)malloc(dst_len + 1);
            strncpy(dst, pipe + 1, dst_len); dst[dst_len] = '\0';
            
            char *n_src = normalize_path(src);
            char *n_dst = normalize_path(dst);
            if (n_src && n_dst) add_rule(&new_rules, n_src, n_dst);
            
            free(src); free(dst);
            free(n_src); free(n_dst);
        }
        if (*end == '\0') break;
        start = end + 1;
    }
    
    pthread_mutex_lock(&g_rules_mutex);
    clear_rule_list(&g_rules);
    g_rules = new_rules;
    pthread_mutex_unlock(&g_rules_mutex);
}

static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return NULL;
    if (strncmp(pathname, "/storage", 8) != 0) return NULL;
    
    char* current = normalize_path(pathname);
    if (!current) return NULL;
    
    char* result = NULL;
    pthread_mutex_lock(&g_rules_mutex);
    for (size_t i = 0; i < g_rules.count; i++) {
        RedirectRule* rule = &g_rules.rules[i];
        if (strcmp(current, rule->source) == 0) {
            result = strdup(rule->target);
            break;
        }
        size_t slen = strlen(rule->source);
        if (strncmp(current, rule->source, slen) == 0 && current[slen] == '/') {
            size_t rlen = strlen(rule->target) + strlen(current + slen) + 1;
            result = (char*)malloc(rlen);
            snprintf(result, rlen, "%s%s", rule->target, current + slen);
            break;
        }
    }
    pthread_mutex_unlock(&g_rules_mutex);
    free(current);
    return result;
}

// ==========================================
// Hook 实现
// ==========================================

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    if (g_is_hooking) return orig_openat(dirfd, pathname, flags, mode);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_openat(dirfd, r ? r : pathname, flags, mode);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (g_is_hooking) return orig_faccessat(dirfd, pathname, mode, flags);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_faccessat(dirfd, r ? r : pathname, mode, flags);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (g_is_hooking) return orig_mkdirat(dirfd, pathname, mode);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_mkdirat(dirfd, r ? r : pathname, mode);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (g_is_hooking) return orig_fstatat(dirfd, pathname, buf, flags);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_fstatat(dirfd, r ? r : pathname, buf, flags);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_access(const char *pathname, int mode) {
    if (g_is_hooking) return orig_access(pathname, mode);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_access(r ? r : pathname, mode);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_stat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_stat(pathname, buf);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_stat(r ? r : pathname, buf);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_lstat(const char *pathname, struct stat *buf) {
    if (g_is_hooking) return orig_lstat(pathname, buf);
    g_is_hooking = true;
    char* r = get_redirected_path(pathname);
    int ret = orig_lstat(r ? r : pathname, buf);
    if (r) free(r);
    g_is_hooking = false;
    return ret;
}

static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    if (g_is_hooking) return orig_getdents64(fd, dirp, count);
    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0) return nread;

    g_is_hooking = true;
    char path[PATH_MAX];
    char procfd[64];
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(procfd, path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        if (strncmp(path, "/storage", 8) == 0) {
            pthread_mutex_lock(&g_rules_mutex);
            char* c_dir = normalize_path(path);
            if (c_dir) {
                int new_n = 0;
                int pos = 0;
                char* b = (char*)dirp;
                while (pos < nread) {
                    struct linux_dirent64 *d = (struct linux_dirent64 *)(b + pos);
                    bool hide = false;
                    for (size_t i = 0; i < g_rules.count; i++) {
                        char* slash = strrchr(g_rules.rules[i].source, '/');
                        if (slash) {
                            size_t dlen = slash - g_rules.rules[i].source;
                            if (strncmp(c_dir, g_rules.rules[i].source, dlen) == 0 &&
                                c_dir[dlen] == '\0' &&
                                strcmp(d->d_name, slash + 1) == 0) {
                                hide = true; break;
                            }
                        }
                    }
                    if (!hide) {
                        if (new_n != pos) memmove(b + new_n, b + pos, d->d_reclen);
                        new_n += d->d_reclen;
                    }
                    pos += d->d_reclen;
                }
                nread = new_n;
                free(c_dir);
            }
            pthread_mutex_unlock(&g_rules_mutex);
        }
    }
    g_is_hooking = false;
    return nread;
}

// ==========================================
// Companion (Root Process)
// ==========================================

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) { close(client_fd); return; }
    buf[len] = '\0';
    
    char pkg_name[256];
    int pid = 0;
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        close(client_fd); return;
    }
    
    // 1. 连接 Injector Socket 进行汇报 (Handshake)
    // Injector 会在收到 REPORT 后处理挂载，处理完返回 OK
    // 我们在这里等待，也就间接阻塞了 App
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);
        
        // Companion 连接 Injector 的超时，防止 Injector 卡死
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 }; 
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(inj_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report[512];
            snprintf(report, sizeof(report), "REPORT %s %d", pkg_name, pid);
            if (write(inj_fd, report, strlen(report)) > 0) {
                char resp[32];
                // **关键阻塞点**: 等待 Injector 回复 "OK"
                // 这段时间内，APP 端的 read() 也会阻塞
                read(inj_fd, resp, sizeof(resp)); 
            }
        }
        close(inj_fd);
    }
    
    // 2. 读取规则文件
    // 此时 Injector 应该已经处理完挂载或忽略，并更新了规则文件
    char rules_buf[16384] = {0}; 
    int fd = open(RULES_FILE_PATH, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, rules_buf, sizeof(rules_buf) - 1);
        if (n > 0) rules_buf[n] = '\0';
        else strcpy(rules_buf, "SET_RULES:");
        close(fd);
    } else {
        strcpy(rules_buf, "SET_RULES:");
    }
    
    // 3. 返回数据给 App，解除 App 的阻塞
    write(client_fd, rules_buf, strlen(rules_buf));
    close(client_fd);
}

// ==========================================
// Zygisk Module (App Process)
// ==========================================

struct HotReloadArgs {
    zygisk::Api* api;
    char* pkg;
    int pid;
};

static void* hot_reload_thread(void* arg) {
    struct HotReloadArgs* args = (struct HotReloadArgs*)arg;
    pthread_detach(pthread_self());
    
    while (1) {
        sleep(10); 
        int fd = args->api->connectCompanion();
        if (fd >= 0) {
            char req[512];
            snprintf(req, sizeof(req), "REQ %s %d", args->pkg, args->pid);
            if (write(fd, req, strlen(req)) > 0) {
                // 热加载不需要 poll 等待太久，Injector 已经知道这个 PID 了
                char buf[16384];
                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    parse_rules_string(buf);
                }
            }
            close(fd);
        }
    }
    free(args->pkg);
    free(args);
    return NULL;
}

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        this->api = api; 
        this->env = env; 
    }
    
    // 阶段 1: 应用 Fork 早期
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* proc_raw = nullptr;
        if (args->nice_name) proc_raw = env->GetStringUTFChars(args->nice_name, nullptr);
        
        this->pkg_name = proc_raw ? strdup(proc_raw) : strdup("unknown");
        this->my_pid = getpid();
        if (proc_raw) env->ReleaseStringUTFChars(args->nice_name, proc_raw);

        // 判定是否为媒体进程
        this->should_hook = is_target_media_process(this->pkg_name);

        // ======================================================
        // 核心握手逻辑 (Handshake & Wait)
        // 任何应用都需要在此处等待 Injector 处理完成 (Mount/Namespace)
        // ======================================================
        
        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req[512];
            snprintf(req, sizeof(req), "REQ %s %d", pkg_name, my_pid);
            if (write(fd, req, strlen(req)) > 0) {
                // 使用 poll 阻塞等待回包
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                
                // **超时设置**: 1000ms (1秒)
                // 如果 Injector 在 1秒内没处理完，我们就不等了，防止应用卡死
                int ret = poll(&pfd, 1, 1000);
                
                if (ret > 0 && (pfd.revents & POLLIN)) {
                    // Injector 处理完毕，读取规则 (即使是空规则)
                    char buf[16384];
                    ssize_t n = read(fd, buf, sizeof(buf) - 1);
                    if (n > 0) {
                        buf[n] = '\0';
                        // 只有媒体进程需要解析规则，其他进程拿到数据后也是丢弃
                        if (should_hook) {
                            parse_rules_string(buf);
                        }
                    }
                } else {
                    LOGD("等待 Injector 超时，跳过 (App: %s)", pkg_name);
                }
            }
            close(fd);
        } else {
            // 连不上 Companion (可能 Zygisk 异常)，直接跳过，不崩溃
            LOGE("无法连接 Companion，跳过握手");
        }
    }
    
    // 阶段 2: 准备完毕，根据身份决定是否卸载
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!should_hook) {
            // 对于普通应用：
            // 握手已在 preAppSpecialize 完成 (Injector 已被通知)
            // 现在可以安全地请求卸载 .so，释放内存
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            
            free(pkg_name);
            pkg_name = NULL;
            return;
        }
        
        // 对于媒体进程：
        // 保留模块，安装 Inline Hook
        LOGI("启用媒体重定向 Hook: %s", pkg_name);
        
        void *h = dlopen("libc.so", RTLD_NOW);
        if (h) {
            #define H(n) do { void* s = dlsym(h, #n); if(s) DobbyHook(s, (void*)fake_##n, (void**)&orig_##n); } while(0)
            H(openat); H(mkdirat); H(faccessat); H(fstatat); 
            H(access); H(stat); H(lstat); H(getdents64);
            dlclose(h);
            g_hooks_installed = true;
        }
        
        // 启动热加载线程
        struct HotReloadArgs* t_args = (struct HotReloadArgs*)malloc(sizeof(struct HotReloadArgs));
        if (t_args) {
            t_args->api = api;
            t_args->pkg = strdup(pkg_name);
            t_args->pid = my_pid;
            pthread_t tid;
            if (pthread_create(&tid, NULL, hot_reload_thread, t_args) != 0) {
                free(t_args->pkg); free(t_args);
            }
        }
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
    char* pkg_name = NULL;
    int my_pid = 0;
    bool should_hook = false;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)