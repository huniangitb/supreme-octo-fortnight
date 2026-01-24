#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <android/log.h>
#include <cerrno>
#include <poll.h>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_NSProxy"
#define TARGET_SOCKET_PATH "/data/Namespace-Proxy/ipc.sock"

// --- 宏定义适配 32/64 位 ---
#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

// --- 全局状态 ---
static std::vector<std::string> g_block_rules;
static std::mutex g_rule_mutex;
static zygisk::Api* g_api = nullptr;
static bool g_is_media_process = false;
static char g_process_name[256] = {"unknown"};
static std::atomic<bool> g_hooks_active(false);

// 原始函数指针
typedef int (*openat_t)(int, const char*, int, mode_t);
typedef int (*mkdirat_t)(int, const char*, mode_t);
static openat_t real_openat = nullptr;
static mkdirat_t real_mkdirat = nullptr;

// --- 日志系统 ---
static void z_log(const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%d][%s] %s", getpid(), g_process_name, msg);
}

// --- 路径拦截逻辑 ---
static bool is_path_blocked(const char* path) {
    if (!path) return false;
    // 硬编码规则
    if (strstr(path, "/storage/emulated/0/Download/1DMP")) return true;
    
    // 动态规则
    if (g_block_rules.empty()) return false;
    std::lock_guard<std::mutex> lock(g_rule_mutex);
    for (const auto& prefix : g_block_rules) {
        if (strstr(path, prefix.c_str())) return true;
    }
    return false;
}

// --- 代理函数 ---
int my_openat(int fd, const char* path, int flags, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED openat: %s", path);
        errno = ENOENT;
        return -1;
    }
    return real_openat(fd, path, flags, mode);
}

int my_mkdirat(int fd, const char* path, mode_t mode) {
    if (g_hooks_active && is_path_blocked(path)) {
        z_log("BLOCKED mkdirat: %s", path);
        errno = EACCES;
        return -1;
    }
    return real_mkdirat(fd, path, mode);
}

// --- TinyHook: 自定义 ELF PLT/GOT Hook 实现 ---
namespace TinyHook {

    struct HookContext {
        const char* symbol_name;
        void* new_func;
        int success_count;
    };

    // 获取页面对齐地址
    uintptr_t page_start(uintptr_t addr) {
        return addr & (~(getpagesize() - 1));
    }

    // 修改内存权限并写入
    bool patch_address(uintptr_t addr, void* new_func) {
        uintptr_t page = page_start(addr);
        if (mprotect((void*)page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            // 如果跨页，可能需要处理 size * 2，这里简化处理
            return false;
        }
        
        void** got_entry = (void**)addr;
        *got_entry = new_func;
        
        mprotect((void*)page, getpagesize(), PROT_READ | PROT_EXEC);
        return true;
    }

    // 遍历 ELF 动态段
    int dl_callback(struct dl_phdr_info* info, size_t size, void* data) {
        HookContext* ctx = (HookContext*)data;
        const char* lib_name = info->dlpi_name;

        // 1. 跳过自身、vdso、linker 和 libc (防止无限递归或奔溃)
        // 注意：我们通过 RTLD_NEXT/DEFAULT 拿到了真正的 libc 函数，所以这里不 Patch libc 的导出表，
        // 而是 Patch 其他所有库对 libc 的导入表。
        if (lib_name == nullptr || *lib_name == '\0') return 0; // Skip main exe usually if path is empty (Android specific)
        if (strstr(lib_name, "libc.so") || strstr(lib_name, "libdl.so") || strstr(lib_name, "linker")) return 0;
        // 如果你不想 Hook 自己的模块，可以加判断，但通常 Zygisk 模块加载后不易区分路径

        ElfW(Dyn)* dyn = nullptr;
        ElfW(Word) dyn_sz = 0;
        
        // 2. 寻找 PT_DYNAMIC
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dyn = (ElfW(Dyn)*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                dyn_sz = info->dlpi_phdr[i].p_memsz;
                break;
            }
        }
        if (!dyn) return 0;

        // 3. 解析动态段
        const char* strtab = nullptr;
        ElfW(Sym)* symtab = nullptr;
        ElfW(Rel)* rel = nullptr;
        ElfW(Rela)* rela = nullptr;
        size_t rel_sz = 0;
        size_t rela_sz = 0;
        bool is_rela = false;

        for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_STRTAB: strtab = (const char*)(info->dlpi_addr + d->d_un.d_ptr); break;
                case DT_SYMTAB: symtab = (ElfW(Sym)*)(info->dlpi_addr + d->d_un.d_ptr); break;
                // JMPREL 通常指向 .rel.plt 或 .rela.plt
                case DT_JMPREL: 
                    // 这里需要区分架构，64位通常是 RELA，32位是 REL
                    // 但 Android 有时混用，所以下面依靠 DT_PLTREL 判断类型
                    if (d->d_un.d_ptr) {} // placeholder
                    break; 
                case DT_PLTRELSZ: rel_sz = d->d_un.d_val; break;
                case DT_REL:      rel = (ElfW(Rel)*)(info->dlpi_addr + d->d_un.d_ptr); break;
                case DT_RELSZ:    if (!rel_sz) rel_sz = d->d_un.d_val; break; // fallback
                case DT_RELA:     rela = (ElfW(Rela)*)(info->dlpi_addr + d->d_un.d_ptr); break;
                case DT_RELASZ:   rela_sz = d->d_un.d_val; break;
                case DT_PLTREL:   is_rela = (d->d_un.d_val == DT_RELA); break;
            }
        }
        
        // 重新定位 JMPREL 地址 (PLT Hook 核心)
        // 某些 ELF 把 JMPREL 分开存，某些直接复用 DT_REL/RELA。
        // 最稳妥的方式是再次遍历确认 JMPREL 的地址
        uintptr_t jmprel_addr = 0;
        for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
             if (d->d_tag == DT_JMPREL) {
                 jmprel_addr = info->dlpi_addr + d->d_un.d_ptr;
                 break;
             }
        }

        if (jmprel_addr) {
            if (is_rela) {
                rela = (ElfW(Rela)*)jmprel_addr;
                // 如果是 JMPREL，通常用 PLTRELSZ
            } else {
                rel = (ElfW(Rel)*)jmprel_addr;
            }
        }

        // 4. 遍历重定位表进行 Hook
        // 仅处理 JMPREL (PLT 调用)，如果需要处理全局变量指针引用，还需处理 DT_REL/DT_RELA
        if (is_rela && rela && symtab && strtab) {
            size_t count = rel_sz / sizeof(ElfW(Rela));
            for (size_t i = 0; i < count; ++i) {
                int type = ELF_R_TYPE(rela[i].r_info);
                int sym_idx = ELF_R_SYM(rela[i].r_info);
                const char* name = strtab + symtab[sym_idx].st_name;
                
                // 常见的 JUMP_SLOT 或 GLOB_DAT
                if (strcmp(name, ctx->symbol_name) == 0) {
                    uintptr_t target_addr = info->dlpi_addr + rela[i].r_offset;
                    if (patch_address(target_addr, ctx->new_func)) {
                        ctx->success_count++;
                    }
                }
            }
        } else if (rel && symtab && strtab) {
            size_t count = rel_sz / sizeof(ElfW(Rel));
            for (size_t i = 0; i < count; ++i) {
                int sym_idx = ELF_R_SYM(rel[i].r_info);
                const char* name = strtab + symtab[sym_idx].st_name;
                
                if (strcmp(name, ctx->symbol_name) == 0) {
                    uintptr_t target_addr = info->dlpi_addr + rel[i].r_offset;
                    if (patch_address(target_addr, ctx->new_func)) {
                        ctx->success_count++;
                    }
                }
            }
        }

        return 0; // 继续遍历下一个库
    }

    void perform_hook(const char* symbol, void* new_func) {
        HookContext ctx = { symbol, new_func, 0 };
        dl_iterate_phdr(dl_callback, &ctx);
        z_log("TinyHook: 已在 %d 个位置 Hook 了符号 %s", ctx.success_count, symbol);
    }
}

// --- 初始化逻辑 ---
static bool init_hooks() {
    // 1. 获取原始 libc 函数地址
    // 使用 RTLD_DEFAULT 确保拿到的是 libc 的实现（或者下一级）
    real_openat = (openat_t)dlsym(RTLD_DEFAULT, "openat");
    real_mkdirat = (mkdirat_t)dlsym(RTLD_DEFAULT, "mkdirat");

    if (!real_openat || !real_mkdirat) {
        z_log("致命错误：无法获取 openat/mkdirat 的原始地址！");
        return false;
    }

    // 2. 执行全量 PLT Hook
    z_log("开始执行全量 PLT 扫描注入...");
    TinyHook::perform_hook("openat", (void*)my_openat);
    TinyHook::perform_hook("mkdirat", (void*)my_mkdirat);

    return true;
}

// --- 异步工作线程 ---
static void async_setup_thread() {
    sleep(1); // 等待其他库加载完毕

    if (init_hooks()) {
        g_hooks_active = true;
        z_log("自定义 Hook 系统激活成功");
    }

    while (true) {
        int fd = g_api->connectCompanion();
        if (fd < 0) {
            // z_log("无法连接 Companion，重试中..."); // 减少日志噪音
            sleep(5);
            continue;
        }

        if (write(fd, "PROXY_CONNECT", 14) <= 0) { close(fd); sleep(1); continue; }
        
        char report[256];
        snprintf(report, sizeof(report), "REPORT %s %d STATUS:CUSTOM_HOOK_ACTIVE", g_process_name, getpid());
        if (write(fd, report, strlen(report)) <= 0) { close(fd); sleep(1); continue; }

        char buf[8192];
        ssize_t len;
        while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[len] = 0;
            if (strncmp(buf, "SET_RULES:", 10) == 0) {
                std::lock_guard<std::mutex> lock(g_rule_mutex);
                g_block_rules.clear();
                char* data = buf + 10; char* token = strtok(data, ",");
                while (token) {
                    if (*token) g_block_rules.emplace_back(token);
                    token = strtok(nullptr, ",");
                }
                z_log("规则更新: %zu 条", g_block_rules.size());
            }
        }
        close(fd);
        sleep(5);
    }
}

// --- Companion 逻辑 (保持不变) ---
static void companion_proxy_bridge(int client_fd, int target_fd) {
    struct pollfd fds[2];
    fds[0].fd = client_fd; fds[0].events = POLLIN;
    fds[1].fd = target_fd; fds[1].events = POLLIN;
    char buffer[4096];

    while (poll(fds, 2, -1) > 0) {
        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & POLLIN) {
                int dest = (i == 0) ? target_fd : client_fd;
                ssize_t n = read(fds[i].fd, buffer, sizeof(buffer));
                if (n <= 0 || write(dest, buffer, n) != n) goto end_bridge;
            }
            if (fds[i].revents & (POLLHUP | POLLERR)) goto end_bridge;
        }
    }
end_bridge:
    close(client_fd);
    close(target_fd);
}

static void companion_handler(int client_fd) {
    char buf[64] = {0};
    if (read(client_fd, buf, sizeof(buf) - 1) <= 0) { close(client_fd); return; }

    if (strcmp(buf, "PROXY_CONNECT") == 0) {
        int target_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, TARGET_SOCKET_PATH, sizeof(addr.sun_path)-1);
        if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(target_fd); close(client_fd); return;
        }
        companion_proxy_bridge(client_fd, target_fd);
    } else {
        close(client_fd);
    }
}

// --- Zygisk 模块入口 ---
class MediaTargetModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { g_api = api; this->env = env; }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char* nice_name = nullptr;
        if (args->nice_name) nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        
        if (nice_name && (
            strstr(nice_name, "android.providers.media") || 
            strstr(nice_name, "android.process.media") ||
            strcmp(nice_name, "com.android.providers.media.module") == 0
        )) {
            g_is_media_process = true; 
            strncpy(g_process_name, nice_name, sizeof(g_process_name)-1);
        }
        
        if (args->nice_name) env->ReleaseStringUTFChars(args->nice_name, nice_name);
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!g_is_media_process) { 
            g_api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); 
            return; 
        }
        // 分离线程进行 Hook 操作，避免阻塞主线程
        std::thread(async_setup_thread).detach();
    }
private:
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MediaTargetModule)
REGISTER_ZYGISK_COMPANION(companion_handler)