#include <jni.h>
#include <unistd.h>
#include <android/log.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <cstring>
#include <string>
#include <thread>
#include "zygisk.hpp"
#include "dobby.h"

#define LOG_TAG "FuseMonitor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::Option;

// --- 基础工具 ---

static uint32_t get_uid_from_fuse_req(void* req) {
    if (!req) return 0;
    return *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(req) + 0x3c);
}

// --- Hook 目标 ---

static void (*orig_pf_open)(void* req, uint64_t ino, void* fi) = nullptr;

void hk_pf_open(void* req, uint64_t ino, void* fi) {
    uint32_t uid = get_uid_from_fuse_req(req);
    // 仅记录日志，不进行任何阻塞操作
    LOGI("[OPEN] UserID: %u | UID: %u | Inode: 0x%llx", uid / 100000, uid, (unsigned long long)ino);
    if (orig_pf_open) orig_pf_open(req, ino, fi);
}

// --- 智能符号查找（精简版） ---

uintptr_t find_pf_open_addr(const char* path, uintptr_t base) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    fstat(fd, &st);
    void* map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    uintptr_t addr = 0;
    auto* ehdr = (Elf64_Ehdr*)map;
    auto* shdrs = (Elf64_Shdr*)((uintptr_t)map + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM) {
            auto* syms = (Elf64_Sym*)((uintptr_t)map + shdrs[i].sh_offset);
            auto* strtab = (char*)((uintptr_t)map + shdrs[shdrs[i].sh_link].sh_offset);
            int count = shdrs[i].sh_size / sizeof(Elf64_Sym);
            for (int j = 0; j < count; j++) {
                const char* name = strtab + syms[j].st_name;
                // 匹配包含 pf_open 且包含 mediaprovider 的符号
                if (strstr(name, "pf_open") && strstr(name, "mediaprovider")) {
                    addr = base + syms[j].st_value;
                    LOGI("Found pf_open symbol: %s at %p", name, (void*)addr);
                    break;
                }
            }
        }
        if (addr) break;
    }
    munmap(map, st.st_size);
    return addr;
}

// --- Zygisk 模块 ---

class FuseMonitorModule : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        if (!args->nice_name) return; // 极其重要：防止系统进程 nice_name 为空时崩溃

        const char* process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process) {
            if (strcmp(process, "com.android.providers.media.module") == 0) {
                is_target = true;
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }

        if (!is_target) {
            api->setOption(Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!is_target) return;

        std::thread([this]() {
            uintptr_t base = 0;
            std::string path;
            
            // 等待库加载
            for (int i = 0; i < 20; i++) {
                FILE* fp = fopen("/proc/self/maps", "re");
                if (fp) {
                    char line[512];
                    while (fgets(line, sizeof(line), fp)) {
                        if (strstr(line, "libfuse_jni.so") && strstr(line, "r-xp")) {
                            char p[256];
                            if (sscanf(line, "%lx-%*x %*s %*s %*s %*s %s", &base, p) == 2) {
                                path = p;
                                break;
                            }
                        }
                    }
                    fclose(fp);
                }
                if (base) break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (base) {
                uintptr_t target_addr = find_pf_open_addr(path.c_str(), base);
                if (target_addr) {
                    DobbyHook((void*)target_addr, (void*)hk_pf_open, (void**)&orig_pf_open);
                    LOGI("Hook pf_open SUCCESS");
                }
            }
        }).detach();
    }

private:
    Api* api = nullptr;
    JNIEnv* env = nullptr;
    bool is_target = false;
};

REGISTER_ZYGISK_MODULE(FuseMonitorModule)