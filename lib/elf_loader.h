#pragma once

#include "iface_handle.h"

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string_view>

namespace dyn {
    struct ElfAddress {
        std::string_view path;
        void* base = nullptr;
        // The containing symbol, when the image has one; empty otherwise.
        std::string_view symbol;
        void* symbolAddress = nullptr;
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

    struct ElfImage: public IfaceHandle {
        virtual ~ElfImage() noexcept;

        // The image's identity, for link_map facades and diagnostics. The
        // path view is NUL-terminated.
        virtual std::string_view path() const = 0;
        virtual uintptr_t base() const = 0;
        virtual const void* dynamicSection() const = 0;

        // The dlvsym lookup: an exact version match in the image's scope.
        virtual void* lookupVersion(std::string_view symbol, std::string_view version) const = 0;

        static ElfImage* loadElf(std::string_view path, int flags);
        static bool findAddress(const void* address, ElfAddress* res);
        static int iterateProgramHeaders(ElfProgramHeaderCallback& callback);

        // The RTLD_DEFAULT search over images loaded with RTLD_GLOBAL.
        static void* lookupGlobal(std::string_view symbol);
        // The RTLD_NEXT search over images loaded after the one holding caller.
        static void* lookupNext(const void* caller, std::string_view symbol, std::string_view version);
    };
}

extern "C" void* elfTlsAddress(const uintptr_t index[2]);
extern "C" void* elfTlsDescAddress(const void* argument);
