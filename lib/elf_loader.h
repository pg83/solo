#pragma once

#include "iface_handle.h"

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string_view>

namespace dyn {
    // Secure-execution mode, ld.so's AT_SECURE discipline: a set-uid,
    // set-gid, or capability-elevated process must not honor the
    // environment's search paths, debug switches, or $-token expansions.
    bool secureExecution();

    // One comma-separated LD_DEBUG in ld.so's shape. glibc's own flags keep
    // their meanings (libs, bindings), the bridge adds stubs, dlfcn, and
    // bridge, and "all" turns everything on. Always false under AT_SECURE.
    bool debugFlag(std::string_view flag);

    // ld.so's LD_TRACE_LOADED_OBJECTS, in ldd's arrow format on stdout.
    // Mapped files print their resolved path and base; names served without
    // a mapping — the ABI bridges and the static providers linked into the
    // executable — print who provided them instead.
    bool traceLoadedObjects();
    void traceProvider(std::string_view name, const char* provider);

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

    // The main program's in-memory program headers and load base, from the
    // auxiliary vector, or from the mapped ELF header when the loading
    // environment left AT_PHDR empty; count is 0 when neither source works.
    struct ElfMainProgram {
        const Elf64_Phdr* headers = nullptr;
        Elf64_Half count = 0;
        uintptr_t base = 0;
    };

    ElfMainProgram elfMainProgram();

    struct ElfImage: public IfaceHandle {
        static constexpr Kind kind = Kind::Image;

        virtual ~ElfImage() noexcept;

        Kind handleKind() const final;

        // The image's identity, for link_map facades and diagnostics. The
        // path view is NUL-terminated.
        virtual std::string_view path() const = 0;
        virtual uintptr_t base() const = 0;
        virtual const void* dynamicSection() const = 0;

        // The dlvsym lookup: an exact version match in the image's scope.
        virtual void* lookupVersion(std::string_view symbol, std::string_view version) const = 0;

        static ElfImage* loadElf(std::string_view path, int flags);
        // The dlopen entry from loaded code: callerIndex names the issuing
        // image through the loader's dlopen caller pool, and its
        // DT_RPATH/DT_RUNPATH join the search. An out-of-pool index (~0u)
        // means no caller.
        static ElfImage* loadElfForCaller(unsigned callerIndex, std::string_view path, int flags);
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
