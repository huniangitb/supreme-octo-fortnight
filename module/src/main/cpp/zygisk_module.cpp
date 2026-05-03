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
#include <unistd.h>
#define LOG_TAG "FuseMonitor"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ==========================================
// RAII 封装 mmap 资源
// ==========================================
struct MappedFile {
    void*  addr   = nullptr;
    size_t length = 0;

    ~MappedFile() {
        if (addr && addr != MAP_FAILED)
            munmap(addr, length);
    }

    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& other) noexcept : addr(other.addr), length(other.length) {
        other.addr = nullptr;
    }
};

static MappedFile map_file_readonly(const char* path) {
    MappedFile mf;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return mf;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return mf;
    }

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

// ==========================================
// 增强的符号智能匹配
// 1. 优先精确匹配 → 2. 包含关键词且在 mediaprovider::fuse 命名空间 → 3. 符号表回退 → 4. 重定位表
// ==========================================
static SymbolResult find_symbol_smart(const char* lib_path, uintptr_t base_addr, const std::string& target) {
    SymbolResult result;

    auto mf = map_file_readonly(lib_path);
    if (!mf.addr) {
        LOGE("Cannot mmap %s", lib_path);
        return result;
    }

    auto* ehdr = (Elf64_Ehdr*)mf.addr;
    // 基本校验
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        LOGE("Invalid ELF header in %s", lib_path);
        return result;
    }

    auto* shdrs = (Elf64_Shdr*)((uintptr_t)mf.addr + ehdr->e_shoff);
    auto* shstrtab = (const char*)((uintptr_t)mf.addr + shdrs[ehdr->e_shstrndx].sh_offset);

    // 先收集所有符号表 section
    struct SymTabInfo {
        Elf64_Sym* syms;
        const char* strtab;
        int count;
        bool is_dynamic; // 动态符号表可能在 .dynsym，更可靠
    };
    std::vector<SymTabInfo> symtabs;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM) {
            SymTabInfo info;
            info.syms = (Elf64_Sym*)((uintptr_t)mf.addr + shdrs[i].sh_offset);
            info.strtab = (const char*)((uintptr_t)mf.addr + shdrs[shdrs[i].sh_link].sh_offset);
            info.count = shdrs[i].sh_size / sizeof(Elf64_Sym);
            info.is_dynamic = (shdrs[i].sh_type == SHT_DYNSYM);
            symtabs.push_back(info);
        }
    }

    // 多层匹配策略
    for (int pass = 0; pass < 3 && !result.address; ++pass) {
        for (const auto& tab : symtabs) {
            for (int j = 0; j < tab.count; ++j) {
                const auto& sym = tab.syms[j];
                const char* name = tab.strtab + sym.st_name;
                if (sym.st_value == 0) continue;

                bool match = false;
                switch (pass) {
                case 0: // 精确全词匹配
                    match = (std::string(name) == target);
                    break;
                case 1: // 包含目标词且属 mediaprovider::fuse 命名空间
                    match = (strstr(name, target.c_str()) != nullptr &&
                             strstr(name, "mediaprovider") != nullptr &&
                             strstr(name, "fuse") != nullptr);
                    break;
                case 2: // 宽泛匹配：只要包含目标词且符号长度合理
                    match = (strstr(name, target.c_str()) != nullptr && strlen(name) > 10);
                    break;
                }
                if (match) {
                    result.address    = base_addr + sym.st_value;
                    result.found_name = name;
                    return result;
                }
            }
        }
    }

    // 回退：如果还是没找到，尝试通过 .rela.plt / .rela.dyn 重定位表寻找导入符号
    // 这里仅检测 _ZL（静态内部链接），通常为 st_value 0，但有些符号表保留。
    // 作为一个简单的 fallback，这里略过，实际可扩展特征码扫描。
    LOGE("Symbol resolution failed for '%s' in %s", target.c_str(), lib_path);
    return result;
}

// ==========================================
// 解析 /proc/self/maps 获取模块基址和路径（增强版，处理路径含空格）
// ==========================================
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
        if (strstr(line, soname) == nullptr) continue;

        // 解析第一列地址和最后一列的完整路径（路径可能含空格，需要从最后一个'/'前提取）
        uintptr_t start = 0;
        if (sscanf(line, "%lx-", &start) != 1) continue;

        // 找到行尾换行符，向前找最后一个 '/'，提取路径
        char* path_start = strrchr(line, '/');
        if (!path_start) continue;
        char* newline = strchr(path_start, '\n');
        if (newline) *newline = '\0';

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
// Hook 监控函数（不拦截，仅记录）
// ==========================================
// 原始函数指针
static void (*orig_pf_read)(void* req, uint64_t ino, size_t size, off_t off, void* fi) = nullptr;
static void (*orig_pf_write)(void* req, uint64_t ino, const char* buf, size_t size, off_t off, void* fi) = nullptr;

// UID 提取（偏移 0x3c 已验证）
static uint32_t get_uid_from_fuse_req(void* req) {
    return *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(req) + 0x3c);
}

void hk_pf_read(void* req, uint64_t ino, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[IO_READ] UID=%u | Inode=%llu | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_read) orig_pf_read(req, ino, size, off, fi);
}

void hk_pf_write(void* req, uint64_t ino, const char* buf, size_t size, off_t off, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    LOGI("[IO_WRITE] UID=%u | Inode=%llu | Size=%zu | Off=%lld",
         uid, (unsigned long long)ino, size, (long long)off);
    if (orig_pf_write) orig_pf_write(req, ino, buf, size, off, fi);
}

// ==========================================
// Zygisk 模块
// ==========================================
class FuseMonitorModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        // 保存 JavaVM，供子线程使用 JNI（当前未使用，但保留）
        env->GetJavaVM(&jvm);
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        // 从 nice_name 获取进程名（此时在主线程，JNI 安全）
        const char* process = env->GetStringUTFChars(args->nice_name, nullptr);
        target_process = (process && std::strcmp(process, "com.android.providers.media.module") == 0);
        env->ReleaseStringUTFChars(args->nice_name, process);
        if (target_process) {
            LOGI("Target MediaProvider process detected, will install hooks.");
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!target_process) return;

        std::thread([this]() {
            install_hooks_async();
        }).detach();
    }

private:
    Api*     api = nullptr;
    JNIEnv*  env = nullptr;
    JavaVM*  jvm = nullptr;
    bool     target_process = false;

    void install_hooks_async() {
        // 等待 libfuse_jni.so 加载
        ModuleInfo mod;
        for (int i = 0; i < 20; ++i) { // 最多等 10 秒
            mod = find_module_in_maps("libfuse_jni.so");
            if (mod.base) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        if (!mod.base) {
            LOGE("libfuse_jni.so not loaded, aborting.");
            return;
        }
        LOGI("Found libfuse_jni.so base=%p path=%s", (void*)mod.base, mod.path.c_str());

        // Hook pf_read
        auto sym_read = find_symbol_smart(mod.path.c_str(), mod.base, "pf_read");
        if (sym_read.address) {
            LOGI("Resolved pf_read as '%s' @ %p", sym_read.found_name.c_str(), (void*)sym_read.address);
            if (DobbyHook((void*)sym_read.address, (void*)hk_pf_read, (void**)&orig_pf_read) == 0) {
                LOGI("pf_read hook installed successfully.");
            } else {
                LOGE("DobbyHook failed for pf_read.");
            }
        } else {
            LOGE("Could not resolve pf_read symbol.");
        }

        // Hook pf_write
        auto sym_write = find_symbol_smart(mod.path.c_str(), mod.base, "pf_write");
        if (sym_write.address) {
            LOGI("Resolved pf_write as '%s' @ %p", sym_write.found_name.c_str(), (void*)sym_write.address);
            if (DobbyHook((void*)sym_write.address, (void*)hk_pf_write, (void**)&orig_pf_write) == 0) {
                LOGI("pf_write hook installed successfully.");
            } else {
                LOGE("DobbyHook failed for pf_write.");
            }
        } else {
            LOGE("Could not resolve pf_write symbol.");
        }
    }
};

REGISTER_ZYGISK_MODULE(FuseMonitorModule)