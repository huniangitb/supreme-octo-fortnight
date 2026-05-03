#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "FuseMonitor"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ==========================================
// RAII mmap 封装
// ==========================================
struct MappedFile {
    void*  addr   = nullptr;
    size_t length = 0;

    ~MappedFile() {
        if (addr && addr != MAP_FAILED) munmap(addr, length);
    }

    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& rhs) noexcept : addr(rhs.addr), length(rhs.length) {
        rhs.addr = nullptr;
    }
};

static MappedFile map_file_readonly(const char* path) {
    MappedFile mf;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return mf;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return mf; }

    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return mf;

    mf.addr   = p;
    mf.length = st.st_size;
    return mf;
}

// ==========================================
// 符号解析结果
// ==========================================
struct SymbolResult {
    uintptr_t   address = 0;
    std::string found_name;
};

// 增强的符号智能查找：精确 -> 包含关键词且属于 mediaprovider::fuse -> 宽泛包含 -> 失败
static SymbolResult find_symbol_smart(const char* lib_path, uintptr_t base_addr, const std::string& target) {
    SymbolResult result;
    auto mf = map_file_readonly(lib_path);
    if (!mf.addr) {
        LOGE("Cannot mmap %s", lib_path);
        return result;
    }

    auto* ehdr = (Elf64_Ehdr*)mf.addr;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        LOGE("Invalid ELF header in %s", lib_path);
        return result;
    }

    auto* shdrs = (Elf64_Shdr*)((uintptr_t)mf.addr + ehdr->e_shoff);
    auto* shstrtab = (const char*)((uintptr_t)mf.addr + shdrs[ehdr->e_shstrndx].sh_offset);

    struct SymTabInfo {
        Elf64_Sym*   syms;
        const char*  strtab;
        int          count;
        bool         is_dynamic;
    };
    std::vector<SymTabInfo> symtabs;

    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM) {
            SymTabInfo info;
            info.syms = (Elf64_Sym*)((uintptr_t)mf.addr + shdrs[i].sh_offset);
            info.strtab = (const char*)((uintptr_t)mf.addr + shdrs[shdrs[i].sh_link].sh_offset);
            info.count = shdrs[i].sh_size / sizeof(Elf64_Sym);
            info.is_dynamic = (shdrs[i].sh_type == SHT_DYNSYM);
            symtabs.push_back(info);
        }
    }

    for (int pass = 0; pass < 3 && !result.address; ++pass) {
        for (const auto& tab : symtabs) {
            for (int j = 0; j < tab.count; ++j) {
                const auto& sym = tab.syms[j];
                const char* name = tab.strtab + sym.st_name;
                if (sym.st_value == 0) continue;

                bool match = false;
                switch (pass) {
                case 0: match = (std::string(name) == target); break;
                case 1: match = (strstr(name, target.c_str()) != nullptr &&
                                 strstr(name, "mediaprovider") != nullptr &&
                                 strstr(name, "fuse") != nullptr);
                        break;
                case 2: match = (strstr(name, target.c_str()) != nullptr && strlen(name) > 10); break;
                }
                if (match) {
                    result.address = base_addr + sym.st_value;
                    result.found_name = name;
                    return result;
                }
            }
        }
    }
    LOGE("Symbol resolution failed for '%s' in %s", target.c_str(), lib_path);
    return result;
}

// 解析 /proc/self/maps 获取模块基址和路径
struct ModuleInfo {
    uintptr_t   base;
    std::string path;
};

static ModuleInfo find_module_in_maps(const char* soname) {
    ModuleInfo info{0, {}};
    FILE* fp = fopen("/proc/self/maps", "re");
    if (!fp) return info;

    char* line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, fp) > 0) {
        if (!strstr(line, soname)) continue;

        uintptr_t start = 0;
        if (sscanf(line, "%lx-", &start) != 1) continue;

        char* path_start = strrchr(line, '/');
        if (!path_start) continue;
        char* nl = strchr(path_start, '\n');
        if (nl) *nl = '\0';

        if (info.base == 0 || start < info.base) {
            info.base = start;
            info.path = path_start;
        }
    }
    free(line);
    fclose(fp);
    return info;
}

// ==========================================
// UID 提取 (fuse_req_t 偏移 0x3c)
// ==========================================
static uint32_t get_uid_from_fuse_req(void* req) {
    return *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(req) + 0x3c);
}

// ==========================================
// 所有监控 Hook 的原型与原始函数指针
// ==========================================
// --- 文件/目录打开与关闭 ---
static void (*orig_pf_open)(void* req, uint64_t ino, void* fi) = nullptr;
static void (*orig_pf_opendir)(void* req, uint64_t ino, void* fi) = nullptr;
static void (*orig_pf_release)(void* req, uint64_t ino, void* fi) = nullptr;
static void (*orig_pf_releasedir)(void* req, uint64_t ino, void* fi) = nullptr;

// --- 读写 ---
static void (*orig_pf_read)(void* req, uint64_t ino, size_t size, off_t off, void* fi) = nullptr;
static void (*orig_pf_write)(void* req, uint64_t ino, const char* buf, size_t size, off_t off, void* fi) = nullptr;

// --- 枚举目录 ---
static void (*orig_pf_readdir)(void* req, uint64_t ino, size_t size, off_t off, void* fi) = nullptr;
static void (*orig_pf_readdirplus)(void* req, uint64_t ino, size_t size, off_t off, void* fi) = nullptr;

// --- 创建 ---
static void (*orig_pf_create)(void* req, uint64_t parent, const char* name, uint32_t mode, void* fi) = nullptr;
static void (*orig_pf_mkdir)(void* req, uint64_t parent, const char* name, uint32_t mode) = nullptr;
static void (*orig_pf_mknod)(void* req, uint64_t parent, const char* name, uint32_t mode, uint64_t rdev) = nullptr;

// --- 删除 ---
static void (*orig_pf_unlink)(void* req, uint64_t parent, const char* name) = nullptr;
static void (*orig_pf_rmdir)(void* req, uint64_t parent, const char* name) = nullptr;

// --- 重命名 ---
static void (*orig_pf_rename)(void* req, uint64_t parent, const char* name, uint64_t newparent, const char* newname, uint32_t flags) = nullptr;

// --- 属性获取 ---
static void (*orig_pf_getattr)(void* req, uint64_t ino, void* fi) = nullptr;

// --- 查找 ---
static void (*orig_pf_lookup)(void* req, uint64_t parent, const char* name) = nullptr;

// --- 辅助宏：打印名称（处理 nullptr） ---
#define SAFE_STR(p) ((p) ? (p) : "(null)")

// ==========================================
// Hook 实现：仅记录，不拦截
// ==========================================

void hk_pf_open(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    uint32_t flags = fi ? *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(fi) + 0x40) : 0;
    LOGI("[OPEN] UID=%u | Inode=0x%llx | Flags=0x%x", uid, (unsigned long long)ino, flags);
    if (orig_pf_open) orig_pf_open(req, ino, fi);
}

void hk_pf_opendir(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[OPENDIR] UID=%u | Inode=0x%llx", uid, (unsigned long long)ino);
    if (orig_pf_opendir) orig_pf_opendir(req, ino, fi);
}

void hk_pf_release(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[RELEASE] UID=%u | Inode=0x%llx", uid, (unsigned long long)ino);
    if (orig_pf_release) orig_pf_release(req, ino, fi);
}

void hk_pf_releasedir(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[RELEASEDIR] UID=%u | Inode=0x%llx", uid, (unsigned long long)ino);
    if (orig_pf_releasedir) orig_pf_releasedir(req, ino, fi);
}

void hk_pf_read(void* req, uint64_t ino, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[READ] UID=%u | Inode=0x%llx | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_read) orig_pf_read(req, ino, size, off, fi);
}

void hk_pf_write(void* req, uint64_t ino, const char* buf, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[WRITE] UID=%u | Inode=0x%llx | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_write) orig_pf_write(req, ino, buf, size, off, fi);
}

void hk_pf_readdir(void* req, uint64_t ino, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[READDIR] UID=%u | Inode=0x%llx | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_readdir) orig_pf_readdir(req, ino, size, off, fi);
}

void hk_pf_readdirplus(void* req, uint64_t ino, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[READDIRPLUS] UID=%u | Inode=0x%llx | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_readdirplus) orig_pf_readdirplus(req, ino, size, off, fi);
}

void hk_pf_create(void* req, uint64_t parent, const char* name, uint32_t mode, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[CREATE] UID=%u | Parent=0x%llx | Name=%s | Mode=0%o",
         uid, (unsigned long long)parent, SAFE_STR(name), mode);
    if (orig_pf_create) orig_pf_create(req, parent, name, mode, fi);
}

void hk_pf_mkdir(void* req, uint64_t parent, const char* name, uint32_t mode) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[MKDIR] UID=%u | Parent=0x%llx | Name=%s | Mode=0%o",
         uid, (unsigned long long)parent, SAFE_STR(name), mode);
    if (orig_pf_mkdir) orig_pf_mkdir(req, parent, name, mode);
}

void hk_pf_mknod(void* req, uint64_t parent, const char* name, uint32_t mode, uint64_t rdev) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[MKNOD] UID=%u | Parent=0x%llx | Name=%s | Mode=0%o | Rdev=0x%llx",
         uid, (unsigned long long)parent, SAFE_STR(name), mode, (unsigned long long)rdev);
    if (orig_pf_mknod) orig_pf_mknod(req, parent, name, mode, rdev);
}

void hk_pf_unlink(void* req, uint64_t parent, const char* name) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[UNLINK] UID=%u | Parent=0x%llx | Name=%s",
         uid, (unsigned long long)parent, SAFE_STR(name));
    if (orig_pf_unlink) orig_pf_unlink(req, parent, name);
}

void hk_pf_rmdir(void* req, uint64_t parent, const char* name) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[RMDIR] UID=%u | Parent=0x%llx | Name=%s",
         uid, (unsigned long long)parent, SAFE_STR(name));
    if (orig_pf_rmdir) orig_pf_rmdir(req, parent, name);
}

void hk_pf_rename(void* req, uint64_t parent, const char* name, uint64_t newparent, const char* newname, uint32_t flags) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[RENAME] UID=%u | OldParent=0x%llx OldName=%s -> NewParent=0x%llx NewName=%s | Flags=0x%x",
         uid, (unsigned long long)parent, SAFE_STR(name),
         (unsigned long long)newparent, SAFE_STR(newname), flags);
    if (orig_pf_rename) orig_pf_rename(req, parent, name, newparent, newname, flags);
}

void hk_pf_getattr(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[GETATTR] UID=%u | Inode=0x%llx", uid, (unsigned long long)ino);
    if (orig_pf_getattr) orig_pf_getattr(req, ino, fi);
}

void hk_pf_lookup(void* req, uint64_t parent, const char* name) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[LOOKUP] UID=%u | Parent=0x%llx | Name=%s",
         uid, (unsigned long long)parent, SAFE_STR(name));
    if (orig_pf_lookup) orig_pf_lookup(req, parent, name);
}

// ==========================================
// Zygisk 模块
// ==========================================
class FuseMonitorModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        env->GetJavaVM(&jvm);
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        const char* process = env->GetStringUTFChars(args->nice_name, nullptr);
        target_process = (process && std::strcmp(process, "com.android.providers.media.module") == 0);
        env->ReleaseStringUTFChars(args->nice_name, process);
        if (target_process) {
            LOGI("Target MediaProvider detected, hooks will be installed.");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!target_process) return;
        std::thread([this]() { install_all_hooks(); }).detach();
    }

private:
    Api*    api = nullptr;
    JNIEnv* env = nullptr;
    JavaVM* jvm = nullptr;
    bool    target_process = false;

    void install_all_hooks() {
        ModuleInfo mod;
        for (int i = 0; i < 20; ++i) {
            mod = find_module_in_maps("libfuse_jni.so");
            if (mod.base) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        if (!mod.base) {
            LOGE("libfuse_jni.so not found, aborting.");
            return;
        }
        LOGI("libfuse_jni.so base=%p path=%s", (void*)mod.base, mod.path.c_str());

        // 辅助宏：尝试 hook 一个符号，失败只打印错误
        auto try_hook = [&](const std::string& sym, void* hk_func, void** orig_ptr) {
            auto res = find_symbol_smart(mod.path.c_str(), mod.base, sym);
            if (res.address) {
                LOGI("Hook %-12s -> %s @ %p", sym.c_str(), res.found_name.c_str(), (void*)res.address);
                if (DobbyHook((void*)res.address, hk_func, orig_ptr) != 0) {
                    LOGE("DobbyHook failed for %s", sym.c_str());
                }
            } else {
                LOGE("Symbol not found: %s", sym.c_str());
            }
        };

        try_hook("pf_open",           (void*)hk_pf_open,          (void**)&orig_pf_open);
        try_hook("pf_opendir",        (void*)hk_pf_opendir,       (void**)&orig_pf_opendir);
        try_hook("pf_release",        (void*)hk_pf_release,       (void**)&orig_pf_release);
        try_hook("pf_releasedir",     (void*)hk_pf_releasedir,    (void**)&orig_pf_releasedir);
        try_hook("pf_read",           (void*)hk_pf_read,          (void**)&orig_pf_read);
        try_hook("pf_write",          (void*)hk_pf_write,         (void**)&orig_pf_write);
        try_hook("pf_readdir",        (void*)hk_pf_readdir,       (void**)&orig_pf_readdir);
        try_hook("pf_readdirplus",    (void*)hk_pf_readdirplus,   (void**)&orig_pf_readdirplus);
        try_hook("pf_create",         (void*)hk_pf_create,        (void**)&orig_pf_create);
        try_hook("pf_mkdir",          (void*)hk_pf_mkdir,         (void**)&orig_pf_mkdir);
        try_hook("pf_mknod",          (void*)hk_pf_mknod,         (void**)&orig_pf_mknod);
        try_hook("pf_unlink",         (void*)hk_pf_unlink,        (void**)&orig_pf_unlink);
        try_hook("pf_rmdir",          (void*)hk_pf_rmdir,         (void**)&orig_pf_rmdir);
        try_hook("pf_rename",         (void*)hk_pf_rename,        (void**)&orig_pf_rename);
        try_hook("pf_getattr",        (void*)hk_pf_getattr,       (void**)&orig_pf_getattr);
        try_hook("pf_lookup",         (void*)hk_pf_lookup,        (void**)&orig_pf_lookup);

        LOGI("Hook installation complete (some may have failed due to symbol unavailability).");
    }
};

REGISTER_ZYGISK_MODULE(FuseMonitorModule)