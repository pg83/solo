#include "musl_provider.h"

#include "dlfcn.h"
#include "elf_loader.h"

#include <cstdint>

namespace {
    static int translateDlopenFlags(int flags) {
        constexpr int muslRtldLazy = 1;
        constexpr int muslRtldNow = 2;
        constexpr int muslRtldNoload = 4;
        constexpr int muslRtldGlobal = 256;
        constexpr int muslRtldNodelete = 4096;

        int translated = flags & muslRtldLazy ? RTLD_LAZY : 0;
        translated |= flags & muslRtldNow ? RTLD_NOW : 0;
        translated |= flags & muslRtldGlobal ? RTLD_GLOBAL : RTLD_LOCAL;
        translated |= flags & muslRtldNodelete ? RTLD_NODELETE : 0;
        translated |= flags & muslRtldNoload ? RTLD_NOLOAD : 0;

        return translated;
    }

    static void* muslDlopen(const char* path, int flags) {
        return stub_dlopen(path ? path : "", translateDlopenFlags(flags));
    }

    static void* muslDlsym(void* handle, const char* name) {
        if (!handle || handle == reinterpret_cast<void*>(static_cast<uintptr_t>(-1))) {
            return stub_dlsym(nullptr, name);
        }

        return stub_dlsym(handle, name);
    }

    static const MuslSymbol muslOverrides[] = {
        {"__tls_get_addr", reinterpret_cast<void*>(elfTlsAddress)},
        {"dlopen", reinterpret_cast<void*>(muslDlopen)},
        {"dlsym", reinterpret_cast<void*>(muslDlsym)},
    };
}

MuslProvider muslProvider() {
    return {
        MUSL_SYMBOLS,
        MUSL_SYMBOL_COUNT,
        muslOverrides,
        sizeof(muslOverrides) / sizeof(muslOverrides[0]),
    };
}
