#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string_view>

struct ElfAddress {
    std::string_view path;
    void* base;
};

struct ElfProgramHeaders {
    const char* path;
    uintptr_t base;
    const Elf64_Phdr* headers;
    Elf64_Half count;
    size_t tlsModule;
    void* tlsData;
};

struct ElfProgramHeaderCallback {
    virtual int call(const ElfProgramHeaders& image) = 0;
};

struct ElfImage {
    virtual ~ElfImage() noexcept;

    virtual void* lookup(std::string_view symbol) const = 0;

    static ElfImage* loadElf(std::string_view path, int flags);
    static bool findAddress(const void* address, ElfAddress* res);
    static int iterateProgramHeaders(ElfProgramHeaderCallback& callback);
};

extern "C" void* elfTlsAddress(const uintptr_t index[2]);
extern "C" void* elfTlsDescAddress(const void* argument);
