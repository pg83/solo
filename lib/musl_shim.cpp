#include "musl_shim.h"
#include "musl_symbols.h"

#include "dlfcn.h"
#include "elf_loader.h"

#include <cstdint>
#include <string_view>
#include <unordered_map>

namespace {
    int translateDlopenFlags(int flags) {
        constexpr int MUSL_RTLD_LAZY = 1;
        constexpr int MUSL_RTLD_NOW = 2;
        constexpr int MUSL_RTLD_NOLOAD = 4;
        constexpr int MUSL_RTLD_GLOBAL = 256;
        constexpr int MUSL_RTLD_NODELETE = 4096;

        int translated = flags & MUSL_RTLD_LAZY ? RTLD_LAZY : 0;
        translated |= flags & MUSL_RTLD_NOW ? RTLD_NOW : 0;
        translated |= flags & MUSL_RTLD_GLOBAL ? RTLD_GLOBAL : RTLD_LOCAL;
        translated |= flags & MUSL_RTLD_NODELETE ? RTLD_NODELETE : 0;
        translated |= flags & MUSL_RTLD_NOLOAD ? RTLD_NOLOAD : 0;

        return translated;
    }

    void* muslDlopen(const char* path, int flags) {
        return stub_dlopen(path ? path : "", translateDlopenFlags(flags));
    }

    void* muslDlsym(void* handle, const char* name) {
        if (!handle || handle == reinterpret_cast<void*>(static_cast<uintptr_t>(-1))) {
            return stub_dlsym(nullptr, name);
        }

        return stub_dlsym(handle, name);
    }

    int muslDlclose(void* handle) {
        return stub_dlclose(handle);
    }

    char* muslDlerror() {
        return stub_dlerror();
    }

    static const auto& muslProviders() {
        using Providers = std::unordered_map<std::string_view, void*>;
        static const auto* providers = [] {
            auto* result = new Providers();

            result->reserve(MUSL_SYMBOL_COUNT);
            for (size_t index = 0; index < MUSL_SYMBOL_COUNT; ++index) {
                const auto& symbol = MUSL_SYMBOLS[index];

                result->emplace(symbol.name, symbol.address);
            }

            result->insert_or_assign("__tls_get_addr", reinterpret_cast<void*>(elfTlsAddress));
            result->insert_or_assign("dlopen", reinterpret_cast<void*>(muslDlopen));
            result->insert_or_assign("dlsym", reinterpret_cast<void*>(muslDlsym));
            result->insert_or_assign("dlclose", reinterpret_cast<void*>(muslDlclose));
            result->insert_or_assign("dlerror", reinterpret_cast<void*>(muslDlerror));

            return result;
        }();

        return *providers;
    }
}

void* resolveMuslSymbol(std::string_view name) {
    const auto& providers = muslProviders();
    if (auto provider = providers.find(name); provider != providers.end()) {
        return provider->second;
    }

    return nullptr;
}
