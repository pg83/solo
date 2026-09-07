// The jump into a guest solo mapped itself. What the kernel and ld.so
// normally split between themselves happens in-process: the loader has
// mapped the executable and its closure, this file builds the System V
// process stack, and the jump to the guest's own _start comes back into the
// bridge through the executable's __libc_start_main import.

#include "elf_loader.h"

#include <alloca.h>
#include <elf.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#include <vector>

using namespace dyn;

namespace {
    // The process stack a kernel would have built for the guest: argc, the
    // argument and environment pointers, and an auxiliary vector describing
    // the guest executable instead of solo itself.
    static std::vector<uintptr_t> buildStackWords(const ElfExecutable& executable, const char* path, int argc, char** argv) {
        std::vector<uintptr_t> words;

        words.push_back(static_cast<uintptr_t>(argc));
        for (int index = 0; index < argc; ++index) {
            words.push_back(reinterpret_cast<uintptr_t>(argv[index]));
        }
        words.push_back(0);
        for (char** entry = environ; *entry; ++entry) {
            words.push_back(reinterpret_cast<uintptr_t>(*entry));
        }
        words.push_back(0);

        auto auxiliary = [&words](uintptr_t type, uintptr_t value) {
            words.push_back(type);
            words.push_back(value);
        };

        auxiliary(AT_PHDR, executable.programHeaders);
        auxiliary(AT_PHENT, sizeof(Elf64_Phdr));
        auxiliary(AT_PHNUM, executable.programHeaderCount);
        auxiliary(AT_ENTRY, executable.entry);
        auxiliary(AT_BASE, 0);
        auxiliary(AT_EXECFN, reinterpret_cast<uintptr_t>(path));
        // The host truths pass through unchanged; the guest lives in this
        // process, so its page size, ids, and vDSO are ours.
        for (auto type : {AT_PAGESZ, AT_CLKTCK, AT_FLAGS, AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE, AT_RANDOM, AT_PLATFORM, AT_HWCAP, AT_HWCAP2, AT_SYSINFO_EHDR}) {
            auxiliary(type, getauxval(type));
        }
        auxiliary(AT_NULL, 0);

        return words;
    }
}

void dyn::enterExecutableStack(uintptr_t entry, uintptr_t stack) {
    // The System V entry protocol: the stack pointer sits on argc, and
    // the register the guest's _start reads as rtld_fini is zeroed —
    // there is no ld.so whose finalizer could need registering.
#if defined(__x86_64__)
    register uintptr_t entryRegister __asm__("r10") = entry;
    register uintptr_t stackRegister __asm__("r11") = stack;

    __asm__ volatile(
        "mov %%r11, %%rsp\n\t"
        "xor %%edx, %%edx\n\t"
        "xor %%ebp, %%ebp\n\t"
        "jmp *%%r10"
        :
        : "r"(entryRegister), "r"(stackRegister)
        : "memory");
#elif defined(__aarch64__)
    register uintptr_t entryRegister __asm__("x16") = entry;
    register uintptr_t stackRegister __asm__("x17") = stack;

    __asm__ volatile(
        "mov sp, x17\n\t"
        "mov x0, xzr\n\t"
        "mov x29, xzr\n\t"
        "mov x30, xzr\n\t"
        "br x16"
        :
        : "r"(entryRegister), "r"(stackRegister)
        : "memory");
#endif
    __builtin_unreachable();
}

void dyn::enterExecutable(const ElfExecutable& executable, const char* path, int argc, char** argv) {
    auto words = buildStackWords(executable, path, argc, argv);
    auto bytes = words.size() * sizeof(uintptr_t);
    // On this thread's real stack, so the guest keeps the full growable
    // stack below it; solo's frames above are never returned to.
    auto* raw = alloca(bytes + 16);
    auto block = (reinterpret_cast<uintptr_t>(raw) + 15) & ~uintptr_t(15);

    memcpy(reinterpret_cast<void*>(block), words.data(), bytes);
    enterExecutableStack(executable.entry, block);
}
