#pragma once

#include <elf.h>
#include <string>
#include <optional>
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

using ElfProgramHeaderCallback = int (*)(const ElfProgramHeaders& image, void* data);

struct ElfImage {
    virtual ~ElfImage() noexcept;

    virtual void* lookup(const std::string_view& symbol) const = 0;

    static ElfImage* loadElf(const std::string_view& path, int flags);
    static std::optional<ElfAddress> findAddress(const void* address);
    static int iterateProgramHeaders(ElfProgramHeaderCallback callback, void* data);
};

extern "C" void* elfTlsAddress(const uintptr_t index[2]);
extern "C" void* elfTlsDescAddress(const void* argument);
