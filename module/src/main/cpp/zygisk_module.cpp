#pragma once

#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <map>
#include <cstring>
#include <cerrno>

#define LOG_TAG "HOOK_MANAGER"
#define ZLOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ZLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 架构宏适配
#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

// --- 简单的指令缓存刷新 ---
void flush_cache(void* addr, size_t size) {
    __builtin___clear_cache((char*)addr, (char*)addr + size);
}

// --- 内存工具 ---
class MemUtils {
public:
    static uintptr_t page_start(uintptr_t addr) {
        return addr & (~(getpagesize() - 1));
    }

    static bool set_protection(uintptr_t addr, size_t size, int prot) {
        uintptr_t start = page_start(addr);
        uintptr_t end = page_start(addr + size - 1) + getpagesize();
        return mprotect((void*)start, end - start, prot) == 0;
    }
};

// --- ELF 解析器 (内存版) ---
class ElfParser {
public:
    // 在内存中查找已加载的 libc 基址
    static uintptr_t find_libc_base() {
        uintptr_t addr = 0;
        dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
            if (strstr(info->dlpi_name, "libc.so")) {
                *(uintptr_t*)data = info->dlpi_addr;
                return 1;
            }
            return 0;
        }, &addr);
        return addr;
    }

    // 手动解析导出表，不依赖 dlsym
    static void* get_symbol_address(uintptr_t base_addr, const char* symbol_name) {
        if (!base_addr) return nullptr;

        const ElfW(Ehdr)* ehdr = (const ElfW(Ehdr)*)base_addr;
        const ElfW(Phdr)* phdr = (const ElfW(Phdr)*)(base_addr + ehdr->e_phoff);
        
        ElfW(Dyn)* dyn = nullptr;
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dyn = (ElfW(Dyn)*)(base_addr + phdr[i].p_vaddr);
                break;
            }
        }
        if (!dyn) return nullptr;

        const char* strtab = nullptr;
        ElfW(Sym)* symtab = nullptr;
        // 简易哈希表查找略过，直接线性扫描（虽然慢点但在初始化时可接受）
        // 生产环境应解析 DT_HASH / DT_GNU_HASH
        
        for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
            if (d->d_tag == DT_STRTAB) strtab = (const char*)(base_addr + d->d_un.d_ptr);
            if (d->d_tag == DT_SYMTAB) symtab = (ElfW(Sym)*)(base_addr + d->d_un.d_ptr);
        }

        if (!strtab || !symtab) return nullptr;

        // 这里的扫描是假设 dynamic symbol table 没那么大，或者你知道大概位置
        // 严谨实现需要根据 DT_HASH 计算链表，这里为了代码紧凑做简化假设：
        // 扫描前 4096 个符号 (通常 libc 导出符号在 2000 左右)
        for (int i = 0; i < 4096; ++i) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0) {
                return (void*)(base_addr + symtab[i].st_value);
            }
        }
        return nullptr;
    }
};

// --- Hook 管理核心 ---
class HookManager {
private:
    struct HookEntry {
        std::string name;
        void* original_func; // 真实地址
        void* proxy_func;    // 我们的代理函数
        void* trampoline;    // Inline Hook 用 (如果实现了指令修复)
    };

    std::map<std::string, HookEntry> m_hooks;
    std::mutex m_mutex;
    bool m_installed = false;

    // 原始 dlopen 函数指针
    typedef void* (*dlopen_t)(const char*, int);
    typedef void* (*android_dlopen_ext_t)(const char*, int, const void*);
    dlopen_t orig_dlopen = nullptr;
    android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

    // 单例
    HookManager() {}

public:
    static HookManager& getInstance() {
        static HookManager instance;
        return instance;
    }

    // 注册 Hook 规则
    void RegisterHook(const char* name, void* proxy, void** out_orig) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hooks[name] = {name, nullptr, proxy, nullptr};
        // 稍后解析真实地址后回填 out_orig
    }

    bool InstallHooks() {
        if (m_installed) return true;
        ZLOGI("开始安装 Hooks...");

        // 1. 获取原始函数地址 (内存解析法)
        ResolveOriginalFunctions();

        // 2. PLT/GOT Hook (覆盖现有已加载库)
        ApplyPltHooksAll();

        // 3. 监控 dlopen (通过 Hook libdl/libc 中的导出或各个库的导入)
        InstallDlopenMonitor();
        
        // 4. Inline Hook (针对特定顽固函数，可选)
        // InstallInlineHooks(); // 警告：需要复杂的指令修复，下面仅演示逻辑

        m_installed = true;
        return true;
    }

    // 供外部获取原始函数
    void* GetOriginal(const char* name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_hooks.find(name) != m_hooks.end()) {
            return m_hooks[name].original_func;
        }
        return nullptr;
    }

private:
    void ResolveOriginalFunctions() {
        uintptr_t libc_base = ElfParser::find_libc_base();
        if (!libc_base) {
            ZLOGE("严重错误：找不到内存中的 libc.so");
            return;
        }
        ZLOGI("libc base: %p", (void*)libc_base);

        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& pair : m_hooks) {
            // 优先尝试内存解析
            pair.second.original_func = ElfParser::get_symbol_address(libc_base, pair.first.c_str());
            
            // 兜底：如果解析失败，回退到 dlsym (RTLD_DEFAULT)
            if (!pair.second.original_func) {
                pair.second.original_func = dlsym(RTLD_DEFAULT, pair.first.c_str());
                ZLOGI("符号 %s 使用 dlsym 兜底", pair.first.c_str());
            } else {
                ZLOGI("符号 %s 解析成功: %p", pair.first.c_str(), pair.second.original_func);
            }
        }
    }

    // -------------------------------------------------------------------------
    // PLT Hook 引擎
    // -------------------------------------------------------------------------
    static int dl_iterate_callback(struct dl_phdr_info* info, size_t size, void* data) {
        HookManager* mgr = (HookManager*)data;
        const char* name = info->dlpi_name;

        // 过滤：跳过自己、linker、libc (防止递归死锁)
        // 注意：不 Hook libc 意味着 libc 内部调用 (如 fopen 调 openat) 不会被拦截，
        // 如果需要拦截 libc 内部调用，必须使用 Inline Hook。
        if (!name || strstr(name, "linker") || strstr(name, "libc.so") || strstr(name, "libdl.so")) {
            return 0;
        }

        mgr->PatchOneModule(info);
        return 0;
    }

    void PatchOneModule(struct dl_phdr_info* info) {
        // 简化的 ELF 遍历逻辑 (参考之前的回答，这里只写核心)
        ElfW(Dyn)* dyn = nullptr;
        size_t rel_sz = 0; ElfW(Rel)* rel = nullptr;
        size_t rela_sz = 0; ElfW(Rela)* rela = nullptr;
        ElfW(Sym)* symtab = nullptr; const char* strtab = nullptr;
        bool is_rela = false;
        
        // 查找 DYNAMIC 段
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dyn = (ElfW(Dyn)*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                break;
            }
        }
        if (!dyn) return;

        // 解析 Dynamic Tags
        uintptr_t jmprel = 0;
        for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
             switch(d->d_tag) {
                case DT_STRTAB: strtab = (const char*)(info->dlpi_addr + d->d_un.d_ptr); break;
                case DT_SYMTAB: symtab = (ElfW(Sym)*)(info->dlpi_addr + d->d_un.d_ptr); break;
                case DT_JMPREL: jmprel = info->dlpi_addr + d->d_un.d_ptr; break;
                case DT_PLTRELSZ: rel_sz = d->d_un.d_val; rela_sz = d->d_un.d_val; break;
                case DT_PLTREL: is_rela = (d->d_un.d_val == DT_RELA); break;
             }
        }

        if (is_rela) rela = (ElfW(Rela)*)jmprel;
        else rel = (ElfW(Rel)*)jmprel;

        if (!symtab || !strtab || (!rel && !rela)) return;

        // 遍历重定位表
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t count = is_rela ? (rela_sz / sizeof(ElfW(Rela))) : (rel_sz / sizeof(ElfW(Rel)));
        
        for (size_t i = 0; i < count; ++i) {
            int sym_idx = is_rela ? ELF_R_SYM(rela[i].r_info) : ELF_R_SYM(rel[i].r_info);
            uintptr_t offset = is_rela ? rela[i].r_offset : rel[i].r_offset;
            const char* sym_name = strtab + symtab[sym_idx].st_name;

            // 检查是否在我们的 Hook 列表里
            auto it = m_hooks.find(sym_name);
            if (it != m_hooks.end()) {
                DoPatch(info->dlpi_addr + offset, it->second.proxy_func);
            }
            
            // 同时也 Hook dlopen，形成闭环
            if (strcmp(sym_name, "dlopen") == 0) {
                 orig_dlopen = (dlopen_t)ElfParser::get_symbol_address(ElfParser::find_libc_base(), "dlopen"); // 确保这里拿到真的
                 DoPatch(info->dlpi_addr + offset, (void*)ProxyDlopen);
            }
            if (strcmp(sym_name, "android_dlopen_ext") == 0) {
                 DoPatch(info->dlpi_addr + offset, (void*)ProxyAndroidDlopenExt);
            }
        }
    }

    void DoPatch(uintptr_t addr, void* new_func) {
        if (MemUtils::set_protection(addr, sizeof(void*), PROT_READ | PROT_WRITE)) {
            *(void**)addr = new_func;
            MemUtils::set_protection(addr, sizeof(void*), PROT_READ);
        }
    }

    void ApplyPltHooksAll() {
        dl_iterate_phdr(dl_iterate_callback, this);
    }

    // -------------------------------------------------------------------------
    // dlopen 监控代理
    // -------------------------------------------------------------------------
    static void* ProxyDlopen(const char* filename, int flags) {
        auto& mgr = getInstance();
        // 1. 调用原始 dlopen
        void* handle = nullptr;
        if (mgr.orig_dlopen) {
            handle = mgr.orig_dlopen(filename, flags);
        } else {
            // fallback
            handle = dlopen(filename, flags);
        }

        // 2. 触发再次扫描
        if (handle) {
            // 优化：只扫描新加载的库，但在 dl_iterate_phdr 中很难只定位一个
            // 简单起见，重新扫描所有（PatchOneModule 内部幂等，多写几次无妨）
            // 生产环境可以优化为通过 handle 获取 link_map 然后只 Patch 那个
            mgr.ApplyPltHooksAll();
        }
        return handle;
    }

    static void* ProxyAndroidDlopenExt(const char* filename, int flags, const void* extinfo) {
        // 同上逻辑...
        auto& mgr = getInstance();
        void* handle = ((android_dlopen_ext_t)dlsym(RTLD_NEXT, "android_dlopen_ext"))(filename, flags, extinfo);
        if (handle) mgr.ApplyPltHooksAll();
        return handle;
    }

    void InstallDlopenMonitor() {
        // 在 ApplyPltHooksAll 中其实已经顺便把各个库导入的 dlopen 给 Hook 了
        // 这样任何库加载新库，都会走我们的 ProxyDlopen，进而触发新的扫描
        ZLOGI("动态加载监控已激活");
    }

    // -------------------------------------------------------------------------
    // Inline Hook (ARM64 简易版 - 仅演示，慎用)
    // -------------------------------------------------------------------------
    void InstallInlineHooks() {
#if defined(__aarch64__)
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& pair : m_hooks) {
            void* target = pair.second.original_func;
            if (!target) continue;
            
            // 1. 准备跳转指令 (B <offset>)
            // ARM64 B 指令范围 +/- 128MB。如果 Hook 函数太远，需要用 LDR x17, #8; BR x17
            // 这里演示绝对跳转 (LDR x16, [PC, #8]; BR x16) - 16 bytes
            uint32_t trampoline_code[] = {
                0x58000050, // LDR x16, .+8 (current PC + 8)
                0xd61f0200, // BR x16
                0x00000000, // low 32 addr
                0x00000000  // high 32 addr
            };

            // 填入目标地址
            uint64_t proxy_addr = (uint64_t)pair.second.proxy_func;
            memcpy(&trampoline_code[2], &proxy_addr, sizeof(uint64_t));

            // 2. 写入目标函数开头
            if (MemUtils::set_protection((uintptr_t)target, sizeof(trampoline_code), PROT_READ | PROT_WRITE | PROT_EXEC)) {
                // 注意：这里粗暴覆盖了前 16 字节！
                // 如果前 16 字节包含 PC 相对寻址指令，或者是函数的一半，程序会崩溃！
                // 这就是为什么手写 Inline Hook 难的原因。
                // 仅适用于：标准函数头 (STP x29, x30, [SP, #-xx]!) 且不涉及相对寻址
                
                // 备份原始指令以便恢复或制作跳板 (略)
                
                memcpy(target, trampoline_code, sizeof(trampoline_code));
                MemUtils::set_protection((uintptr_t)target, sizeof(trampoline_code), PROT_READ | PROT_EXEC);
                flush_cache(target, sizeof(trampoline_code));
                
                ZLOGI("Inline Hook %s applied (UNSAFE MODE)", pair.first.c_str());
            }
        }
#endif
    }
};