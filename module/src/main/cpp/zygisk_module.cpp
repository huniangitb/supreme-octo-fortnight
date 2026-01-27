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

// 必须包含 zygisk 和 dobby 头文件
#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static const char* INJECTOR_SOCKET_PATH = "/data/Namespace-Proxy/ipc.sock";
static const char* RULES_FILE_PATH = "/data/Namespace-Proxy/zygisk_rules.conf";

// ==========================================
// C 语言数据结构与辅助函数 (无 C++ STL)
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

// 全局变量
static RuleList g_rules = {0};
static pthread_mutex_t g_rules_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_hooks_installed = false;

// 线程局部变量，防止递归 Hook
static __thread bool g_is_hooking = false;

// 原始函数指针
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags);
static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags);
static int (*orig_access)(const char *pathname, int mode);
static int (*orig_stat)(const char *pathname, struct stat *buf);
static int (*orig_lstat)(const char *pathname, struct stat *buf);
// 必须定义 dirent64 结构
struct linux_dirent64 { 
    uint64_t d_ino; 
    int64_t d_off; 
    unsigned short d_reclen; 
    unsigned char d_type; 
    char d_name[]; 
};
static int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

// 辅助：去除路径末尾斜杠
static char* normalize_path(const char* p) {
    if (!p || p[0] == '\0') {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    
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

// 辅助：检查是否为目标媒体进程
static bool is_target_media_process(const char* name) {
    if (!name) return false;
    
    // 这些是常见的媒体存储和扫描进程
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

// 规则列表操作
static void init_rule_list(RuleList* list) {
    list->rules = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool add_rule(RuleList* list, const char* source, const char* target) {
    if (!source || source[0] == '\0') return false;
    
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        RedirectRule* new_rules = (RedirectRule*)realloc(list->rules, new_capacity * sizeof(RedirectRule));
        if (!new_rules) return false;
        
        list->rules = new_rules;
        list->capacity = new_capacity;
    }
    
    RedirectRule* rule = &list->rules[list->count];
    rule->source = strdup(source);
    rule->target = target ? strdup(target) : NULL;
    
    if (!rule->source || (target && !rule->target)) {
        if(rule->source) free(rule->source);
        if(rule->target) free(rule->target);
        return false;
    }
    
    list->count++;
    return true;
}

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

// 解析规则字符串 SET_RULES:src|dst,src2|dst2
static void parse_rules_string(const char* raw_data) {
    if (!raw_data || strncmp(raw_data, "SET_RULES:", 10) != 0) return;
    
    const char* data = raw_data + 10;
    RuleList new_rules = {0};
    init_rule_list(&new_rules);
    
    const char* start = data;
    const char* end;
    
    while (*start) {
        end = strchr(start, ',');
        if (!end) end = start + strlen(start);
        
        char* pipe = (char*)memchr(start, '|', end - start);
        if (pipe) {
            size_t source_len = pipe - start;
            char* source = (char*)malloc(source_len + 1);
            if (source) {
                strncpy(source, start, source_len);
                source[source_len] = '\0';
                
                char* norm_source = normalize_path(source);
                free(source);
                
                if (norm_source && norm_source[0] != '\0') {
                    const char* target_start = pipe + 1;
                    size_t target_len = end - target_start;
                    char* target = (char*)malloc(target_len + 1);
                    if (target) {
                        strncpy(target, target_start, target_len);
                        target[target_len] = '\0';
                        
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
    
    pthread_mutex_lock(&g_rules_mutex);
    clear_rule_list(&g_rules);
    g_rules = new_rules;
    pthread_mutex_unlock(&g_rules_mutex);
    
    LOGD("规则已更新: %zu 条", g_rules.count);
}

// 获取重定向路径
static char* get_redirected_path(const char* pathname) {
    if (!pathname || pathname[0] != '/') return NULL;
    // 性能优化：非 /storage 路径通常不需要处理
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
        
        // 前缀匹配 (目录)
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
    // openat 的第四个参数仅在 flags 包含 O_CREAT 时有效
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_list ap; 
        va_start(ap, flags);
        mode = va_arg(ap, mode_t); 
        va_end(ap);
    }
    
    if (g_is_hooking) return orig_openat(dirfd, pathname, flags, mode);
    g_is_hooking = true;
    
    char* r_path = get_redirected_path(pathname);
    // 注意：这里需要再次传 mode，即使没用到也没关系，但不传 O_CREAT 时会缺参
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

// 危险函数，必须小心处理
static int fake_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    // 如果已经在 Hook 中，直接返回原始调用，防止死递归
    if (g_is_hooking) return orig_getdents64(fd, dirp, count);

    int nread = orig_getdents64(fd, dirp, count);
    if (nread <= 0) return nread;
    
    g_is_hooking = true;

    // 获取当前 fd 对应的路径
    char path[PATH_MAX];
    char procfd[64];
    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
    // readlink 可能会触发其他 hook (如 open/stat)，但我们已经设置了 g_is_hooking
    ssize_t len = readlink(procfd, path, sizeof(path) - 1);
    
    if (len <= 0) {
        g_is_hooking = false;
        return nread;
    }
    path[len] = '\0';
    
    // 仅处理存储路径
    if (strncmp(path, "/storage", 8) != 0) {
        g_is_hooking = false;
        return nread;
    }
    
    pthread_mutex_lock(&g_rules_mutex);
    
    char* current_dir = normalize_path(path);
    if (!current_dir) {
        pthread_mutex_unlock(&g_rules_mutex);
        g_is_hooking = false;
        return nread;
    }
    
    int bpos = 0;
    // 内存移动会导致数据变动，不能简单用 for 循环
    // 创建一个临时缓冲区来构建过滤后的结果，这样更安全
    // 但为了不引入太多 malloc，我们原地修改
    
    int new_nread = 0;
    int current_pos = 0;
    
    // 第一次遍历：执行过滤并压缩
    // 这里采用双指针法：current_pos 是读取位置，new_nread 是写入位置
    // 直接在 dirp 缓冲区内操作
    
    char* buf = (char*)dirp;
    
    while (current_pos < nread) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + current_pos);
        int reclen = d->d_reclen;
        bool hide = false;
        
        // 检查规则
        for (size_t i = 0; i < g_rules.count; i++) {
            RedirectRule* rule = &g_rules.rules[i];
            char* last_slash = strrchr(rule->source, '/');
            if (last_slash) {
                // 如果当前目录是规则的父目录
                size_t dir_len = last_slash - rule->source;
                if (strncmp(current_dir, rule->source, dir_len) == 0 &&
                    current_dir[dir_len] == '\0' &&
                    strcmp(d->d_name, last_slash + 1) == 0) {
                    hide = true;
                    break;
                }
            }
        }
        
        if (!hide) {
            // 如果不隐藏，将此条目移动到新位置（如果位置没变，memmove 也安全）
            if (new_nread != current_pos) {
                memmove(buf + new_nread, buf + current_pos, reclen);
            }
            new_nread += reclen;
        }
        
        current_pos += reclen;
    }
    
    free(current_dir);
    pthread_mutex_unlock(&g_rules_mutex);
    g_is_hooking = false;
    
    return new_nread;
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
    
    // 1. 读取规则文件
    const char* default_rules = "EMPTY";
    char file_buf[8192] = {0};
    const char* rules_content = default_rules;
    
    int file_fd = open(RULES_FILE_PATH, O_RDONLY);
    if (file_fd >= 0) {
        ssize_t n = read(file_fd, file_buf, sizeof(file_buf) - 1);
        if (n > 0) {
            file_buf[n] = '\0';
            rules_content = file_buf;
        }
        close(file_fd);
    }
    
    write(client_fd, rules_content, strlen(rules_content));
    close(client_fd);
}

// ==========================================
// 热加载线程函数
// ==========================================

struct ThreadArgs {
    zygisk::Api* api;
    char* pkg_name;
    int pid;
};

static void* hot_reload_thread(void* arg) {
    struct ThreadArgs* args = (struct ThreadArgs*)arg;
    zygisk::Api* api = args->api;
    char* pkg_name = args->pkg_name;
    int my_pid = args->pid;
    
    // 分离线程
    pthread_detach(pthread_self());
    
    LOGI("热加载线程启动: %s", pkg_name);
    
    while (1) {
        sleep(10); // 10秒检查一次
        
        int fd = api->connectCompanion();
        if (fd < 0) {
            LOGE("连接Companion失败");
            continue;
        }
        
        char req[512];
        snprintf(req, sizeof(req), "REQ %s %d", pkg_name, my_pid);
        
        if (write(fd, req, strlen(req)) > 0) {
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
    free(args);
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
        
        // 复制进程名，因为 Release 后指针失效
        this->pkg_name = proc_raw ? strdup(proc_raw) : strdup("unknown");
        this->my_pid = getpid();
        
        if (proc_raw) {
            env->ReleaseStringUTFChars(args->nice_name, proc_raw);
        }
        
        // **关键判定**：只针对媒体进程启用 Hook
        this->should_hook = is_target_media_process(this->pkg_name);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // **逻辑分支**
        
        if (!should_hook) {
            // 情况 1: 普通 APP
            // 绝对不要安装 Hook，并通知 Zygisk 卸载 .so 释放内存
            // 这是安全的，因为没有修改任何 libc 函数
            LOGD("普通进程 %s，请求卸载模块", pkg_name);
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            
            // 释放本地分配的内存
            free(pkg_name);
            pkg_name = NULL;
            return;
        }
        
        // 情况 2: 媒体进程
        // 安装 Hook，且绝不卸载模块，防止崩溃
        LOGI("检测到媒体进程 %s，开始注入...", pkg_name);
        
        // 先获取一次规则
        fetch_initial_rules();
        
        // 安装 Hook
        install_hooks();
        
        // 启动后台线程
        struct ThreadArgs* t_args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
        if (t_args) {
            t_args->api = api;
            // 线程需要拥有 pkg_name 的副本，主线程的 pkg_name 可能被析构
            t_args->pkg_name = strdup(pkg_name);
            t_args->pid = my_pid;
            
            pthread_t tid;
            if (pthread_create(&tid, NULL, hot_reload_thread, t_args) != 0) {
                free(t_args->pkg_name);
                free(t_args);
            }
        }
        
        // 模块类可能会被销毁（Zygisk机制），但 so 库会保留在内存中
        // 所以我们不在析构函数中 free(pkg_name)，交由线程管理或忽略（进程生命周期级泄漏可接受）
    }
    
private:
    zygisk::Api *api;
    JNIEnv *env;
    char* pkg_name = NULL;
    int my_pid = 0;
    bool should_hook = false;
    
    void fetch_initial_rules() {
        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req[512];
            snprintf(req, sizeof(req), "REQ %s %d", pkg_name, my_pid);
            write(fd, req, strlen(req));
            
            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                parse_rules_string(buf);
            }
            close(fd);
        }
    }
    
    void install_hooks() {
        if (g_hooks_installed) return;
        
        void *h = dlopen("libc.so", RTLD_NOW);
        if (!h) return;
        
        // 宏定义简化 Hook 流程
        #define DO_HOOK(name) \
            do { \
                void* sym = dlsym(h, #name); \
                if (sym) { \
                    DobbyHook(sym, (void*)fake_##name, (void**)&orig_##name); \
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
        LOGI("Hook 安装完成");
    }
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)