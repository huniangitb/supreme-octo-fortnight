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

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

// ==========================================
// C语言数据结构与辅助函数
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
static __thread bool g_is_hooking = false;
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

// 去除路径末尾斜杠
static char* normalize_path(const char* p) {
    if (!p || p[0] == '\0') return strdup("");
    
    size_t len = strlen(p);
    while (len > 1 && p[len - 1] == '/') {
        len--;
    }
    
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    
    strncpy(result, p, len);
    result[len] = '\0';
    return result;
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
    
    for (size_t i = 0; i < sizeof(media_processes)/sizeof(media_processes[0]); i++) {
        if (strstr(name, media_processes[i])) {
            return true;
        }
    }
    return false;
}

// 初始化规则列表
static void init_rule_list(RuleList* list) {
    list->rules = NULL;
    list->count = 0;
    list->capacity = 0;
}

// 添加规则到列表
static bool add_rule(RuleList* list, const char* source, const char* target) {
    if (!source || source[0] == '\0') return false;
    
    // 扩容
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        RedirectRule* new_rules = (RedirectRule*)realloc(list->rules, new_capacity * sizeof(RedirectRule));
        if (!new_rules) return false;
        
        list->rules = new_rules;
        list->capacity = new_capacity;
    }
    
    // 添加新规则
    RedirectRule* rule = &list->rules[list->count];
    rule->source = strdup(source);
    rule->target = target ? strdup(target) : NULL;
    
    if (!rule->source || (target && !rule->target)) {
        free(rule->source);
        free(rule->target);
        return false;
    }
    
    list->count++;
    return true;
}

// 清空规则列表
static void clear_rule_list(RuleList* list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->rules[i].source);
        free(list->rules[i].target);
    }
    free(list->rules);
    list->rules = NULL;
    list->count = 0;
    list->capacity = 0;
}

// 解析规则字符串
static void parse_rules_string(const char* raw_data) {
    if (!raw_data || strncmp(raw_data, "SET_RULES:", 10) != 0) return;
    
    const char* data = raw_data + 10; // 跳过 "SET_RULES:"
    RuleList new_rules = {0};
    init_rule_list(&new_rules);
    
    const char* start = data;
    const char* end;
    
    while (*start) {
        // 查找逗号或字符串结束
        end = strchr(start, ',');
        if (!end) end = start + strlen(start);
        
        // 查找管道符
        const char* pipe = memchr(start, '|', end - start);
        if (pipe) {
            // 提取source部分
            char* source = (char*)malloc(pipe - start + 1);
            if (source) {
                strncpy(source, start, pipe - start);
                source[pipe - start] = '\0';
                
                // 标准化source
                char* norm_source = normalize_path(source);
                free(source);
                
                if (norm_source && norm_source[0] != '\0') {
                    // 提取target部分
                    const char* target_start = pipe + 1;
                    size_t target_len = end - target_start;
                    char* target = (char*)malloc(target_len + 1);
                    if (target) {
                        strncpy(target, target_start, target_len);
                        target[target_len] = '\0';
                        
                        // 标准化target
                        char* norm_target = normalize_path(target);
                        free(target);
                        
                        if (norm_target) {
                            add_rule(&new_rules, norm_source, norm_target);
                            free(norm_target);
                        }
                    }
                }
                free(norm_source);
            }
        }
        
        if (*end == '\0') break;
        start = end + 1;
    }
    
    // 更新全局规则
    pthread_mutex_lock(&g_rules_mutex);
    clear_rule_list(&g_rules);
    g_rules = new_rules;
    pthread_mutex_unlock(&g_rules_mutex);
    
    LOGD("规则库已更新，当前规则数: %zu", g_rules.count);
}

// 获取重定向路径
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return NULL;
    
    // 简单优化：非 /storage 开头直接跳过，提高性能
    if (strncmp(pathname, "/storage", 8) != 0) return NULL;
    
    char* current = normalize_path(pathname);
    if (!current) return NULL;
    
    char* result = NULL;
    size_t current_len = strlen(current);
    
    pthread_mutex_lock(&g_rules_mutex);
    
    for (size_t i = 0; i < g_rules.count; i++) {
        RedirectRule* rule = &g_rules.rules[i];
        
        // 精确匹配
        if (strcmp(current, rule->source) == 0) {
            result = strdup(rule->target);
            break;
        }
        
        // 前缀匹配
        size_t source_len = strlen(rule->source);
        if (current_len > source_len && 
            current[source_len] == '/' &&
            strncmp(current, rule->source, source_len) == 0) {
            
            size_t result_len = strlen(rule->target) + (current_len - source_len) + 1;
            result = (char*)malloc(result_len);
            if (result) {
                snprintf(result, result_len, "%s%s", rule->target, current + source_len);
            }
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
    if (flags & O_CREAT) {
        va_list ap; 
        va_start(ap, flags);
        mode = va_arg(ap, mode_t); 
        va_end(ap);
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
    char procfd[64];
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(procfd, path, sizeof(path) - 1);
    if (len <= 0) return nread;
    path[len] = '\0';
    
    if (strncmp(path, "/storage", 8) != 0) return nread;
    
    pthread_mutex_lock(&g_rules_mutex);
    g_is_hooking = true;
    
    char* current_dir = normalize_path(path);
    if (!current_dir) {
        pthread_mutex_unlock(&g_rules_mutex);
        return nread;
    }
    
    int bpos = 0;
    while (bpos < nread) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)((char *)dirp + bpos);
        bool hide = false;
        
        for (size_t i = 0; i < g_rules.count; i++) {
            RedirectRule* rule = &g_rules.rules[i];
            char* last_slash = strrchr(rule->source, '/');
            if (last_slash) {
                size_t dir_len = last_slash - rule->source;
                if (strncmp(current_dir, rule->source, dir_len) == 0 &&
                    current_dir[dir_len] == '\0' &&
                    strcmp(d->d_name, last_slash + 1) == 0) {
                    hide = true;
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
        } else {
            bpos += d->d_reclen;
        }
    }
    
    free(current_dir);
    g_is_hooking = false;
    pthread_mutex_unlock(&g_rules_mutex);
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
    if (sscanf(buf, "REQ %255s %d", pkg_name, &pid) != 2) {
        close(client_fd); return;
    }
    
    // 1. 上报给 Injector
    int injector_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, INJECTOR_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (injector_fd >= 0) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(injector_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(injector_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(injector_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char report_msg[512];
            snprintf(report_msg, sizeof(report_msg), "REPORT %s %d", pkg_name, pid);
            if (write(injector_fd, report_msg, strlen(report_msg)) > 0) {
                char resp[32];
                read(injector_fd, resp, sizeof(resp));
            }
        }
        close(injector_fd);
    }
    
    // 2. 读取规则文件
    char* rules_content = "EMPTY";
    char file_buf[8192] = {0};
    int file_fd = open(RULES_FILE_PATH, O_RDONLY);
    if (file_fd >= 0) {
        ssize_t n = read(file_fd, file_buf, sizeof(file_buf) - 1);
        if (n > 0) {
            file_buf[n] = '\0';
            rules_content = file_buf;
        }
        close(file_fd);
    }
    
    // 3. 将规则返回给 App
    write(client_fd, rules_content, strlen(rules_content));
    close(client_fd);
}

// ==========================================
// 热加载线程函数
// ==========================================

static void* hot_reload_thread(void* arg) {
    zygisk::Api* api = (zygisk::Api*)arg;
    char* pkg_name = NULL;
    int my_pid = getpid();
    
    // 获取包名
    char proc_name[256];
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        if (fgets(proc_name, sizeof(proc_name), cmdline)) {
            pkg_name = strdup(proc_name);
        }
        fclose(cmdline);
    }
    
    if (!pkg_name) {
        return NULL;
    }
    
    while (1) {
        sleep(5);
        
        int fd = api->connectCompanion();
        if (fd < 0) continue;
        
        char req[512];
        snprintf(req, sizeof(req), "REQ %s %d", pkg_name, my_pid);
        write(fd, req, strlen(req));
        
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 500);
        
        if (ret > 0 && (pfd.revents & POLLIN)) {
            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                parse_rules_string(buf);
            }
        }
        close(fd);
    }
    
    free(pkg_name);
    return NULL;
}

// ==========================================
// Zygisk Module 逻辑 (App 进程)
// ==========================================

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { 
        this->api = api; 
        this->env = env; 
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* proc_raw = nullptr;
        if (args->nice_name) {
            proc_raw = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        
        char* proc_name = proc_raw ? strdup(proc_raw) : strdup("unknown");
        if (proc_raw) {
            env->ReleaseStringUTFChars(args->nice_name, proc_raw);
        }
        
        this->pkg_name = proc_name;
        this->my_pid = getpid();
        
        // 同步获取规则
        fetch_rules_sync(1000);
        
        // 决定是否启用Hook
        this->should_hook = is_target_media_process(proc_name);
        free(proc_name);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!should_hook) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        
        install_hooks();
        
        // 启动热加载线程
        pthread_t tid;
        pthread_create(&tid, NULL, hot_reload_thread, api);
        pthread_detach(tid);
        
        LOGD("[%s] Media Shield 激活", pkg_name);
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
    bool should_hook = false;
    char* pkg_name = NULL;
    int my_pid = 0;
    
    void fetch_rules_sync(int timeout_ms) {
        int fd = api->connectCompanion();
        if (fd < 0) return;
        
        char req[512];
        snprintf(req, sizeof(req), "REQ %s %d", pkg_name, my_pid);
        write(fd, req, strlen(req));
        
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, timeout_ms);
        
        if (ret > 0 && (pfd.revents & POLLIN)) {
            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
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
            do { \
                void* sym_##name = dlsym(h, #name); \
                if (sym_##name) { \
                    DobbyHook(sym_##name, (void*)fake_##name, (void**)&orig_##name); \
                } \
            } while(0)
        
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