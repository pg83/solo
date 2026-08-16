#include "dlfcn.h"
#include "elf_loader.h"
#include "musl_symbols.h"

#include <memory>
#include <stdio.h>
#include <stdint.h>
#include <exception>

namespace {
    using EnumerateInstanceVersion = int32_t (*)(uint32_t* version);
    using DynamicDlsym = void* (*)(void* handle, const char* symbol);
    using GlibcLookup = void* (*)(const char* library, const char* symbol);
    using GlibcDefaultLookup = void* (*)(const char* symbol);
    using GlibcVersionLookup = void* (*)(const char* library, const char* symbol, const char* version);
    using GlibcDlFunction = void* (*)(const char* symbol);
    using GlibcTest = int (*)();

    static int testProviderValue(int value) {
        return value + 35;
    }

    static void* requiredSymbol(void* handle, const char* name) {
        auto* address = stub_dlsym(handle, name);

        if (!address) {
            fprintf(stderr, "glibc test symbol missing: %s: %s\n", name, stub_dlerror());
        }

        return address;
    }
}

int main() {
    auto* libc = stub_dlopen("libc.musl-x86_64.so.1", RTLD_NOW | RTLD_LOCAL);

    if (!libc) {
        fprintf(stderr, "static libc provider failed: %s\n", stub_dlerror());
        return 1;
    }
    for (size_t index = 0; index < MUSL_SYMBOL_COUNT; ++index) {
        if (!stub_dlsym(libc, MUSL_SYMBOLS[index].name)) {
            fprintf(stderr, "static libc symbol missing: %s: %s\n", MUSL_SYMBOLS[index].name, stub_dlerror());
            return 1;
        }
    }
    static constexpr const char* dynamicSymbols[] = {
        "dlopen",
        "dlsym",
        "dlclose",
        "dlerror",
        "dladdr",
    };
    for (const auto* symbol : dynamicSymbols) {
        if (!stub_dlsym(libc, symbol)) {
            fprintf(stderr, "static libc dynamic symbol missing: %s: %s\n", symbol, stub_dlerror());
            return 1;
        }
    }

    auto dynamicDlsym = reinterpret_cast<DynamicDlsym>(stub_dlsym(libc, "dlsym"));
    auto* rawStrchr = stub_dlsym(libc, "strchr");

    if (!dynamicDlsym || dynamicDlsym(nullptr, "strchr") != rawStrchr) {
        fprintf(stderr, "musl RTLD_DEFAULT lookup failed\n");
        return 1;
    }

    stub_dlregister("test-provider", "test_provider_value", reinterpret_cast<void*>(testProviderValue));

    auto* glibc = stub_dlopen("libdlfcn-test-glibc.so", RTLD_NOW | RTLD_LOCAL);

    if (!glibc) {
        fprintf(stderr, "glibc test load failed: %s\n", stub_dlerror());
        return 1;
    }

    auto glibcLookup = reinterpret_cast<GlibcLookup>(requiredSymbol(glibc, "glibc_test_lookup"));
    auto glibcDefaultLookup = reinterpret_cast<GlibcDefaultLookup>(requiredSymbol(glibc, "glibc_test_default_lookup"));
    auto glibcVersionLookup = reinterpret_cast<GlibcVersionLookup>(requiredSymbol(glibc, "glibc_test_version_lookup"));
    auto glibcDlFunction = reinterpret_cast<GlibcDlFunction>(requiredSymbol(glibc, "glibc_test_dl_function"));
    auto glibcFactory = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_factory"));
    auto glibcOwnSymbol = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_own_symbol"));
    auto glibcThread = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_thread"));
    auto glibcManyPthreadObjects = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_many_pthread_objects"));
    auto glibcError = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_error"));
    auto glibcClose = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_close"));

    if (!glibcLookup || !glibcDefaultLookup || !glibcVersionLookup || !glibcDlFunction || !glibcFactory || !glibcOwnSymbol || !glibcThread || !glibcManyPthreadObjects || !glibcError || !glibcClose) {
        return 1;
    }

    static constexpr const char* passthroughSymbols[] = {
        "free",
        "malloc",
        "memcpy",
        "strchr",
        "strlen",
    };
    for (const auto* symbol : passthroughSymbols) {
        auto* expected = stub_dlsym(libc, symbol);
        auto* found = glibcLookup("libc.so.6", symbol);

        if (!expected || found != expected) {
            fprintf(stderr, "glibc libc passthrough failed: %s expected=%p found=%p\n", symbol, expected, found);
            return 1;
        }
    }

    auto* rawCos = stub_dlsym(libc, "cos");

    if (glibcDefaultLookup("strchr") != rawStrchr || glibcDlFunction("strchr") != rawStrchr || glibcLookup("libm.so.6", "cos") != rawCos) {
        fprintf(stderr, "glibc runtime alias passthrough failed\n");
        return 1;
    }
    if (glibcFactory() != 42) {
        fprintf(stderr, "glibc static factory lookup failed\n");
        return 1;
    }
    if (glibcOwnSymbol() != 97) {
        fprintf(stderr, "glibc ELF handle lookup failed\n");
        return 1;
    }

    auto* rawPthreadCreate = stub_dlsym(libc, "pthread_create");
    auto* bridgedPthreadCreate = glibcLookup("libpthread.so.0", "pthread_create");
    auto* oldPthreadCreate = glibcVersionLookup("libc.so.6", "pthread_create", "GLIBC_2.2.5");
    auto* newPthreadCreate = glibcVersionLookup("libc.so.6", "pthread_create", "GLIBC_2.34");

    if (!bridgedPthreadCreate || bridgedPthreadCreate == rawPthreadCreate || oldPthreadCreate != bridgedPthreadCreate || newPthreadCreate != bridgedPthreadCreate || glibcDefaultLookup("pthread_create") != bridgedPthreadCreate) {
        fprintf(stderr, "glibc pthread ABI override failed: raw=%p bridge=%p old=%p new=%p\n", rawPthreadCreate, bridgedPthreadCreate, oldPthreadCreate, newPthreadCreate);
        return 1;
    }
    if (!glibcDlFunction("dlsym") || glibcDlFunction("dlsym") == stub_dlsym(libc, "dlsym")) {
        fprintf(stderr, "glibc libdl ABI override failed\n");
        return 1;
    }
    if (auto result = glibcThread(); result != 0) {
        fprintf(stderr, "glibc pthread bridge execution failed: %d\n", result);
        return 1;
    }
    if (auto result = glibcManyPthreadObjects(); result != 0) {
        fprintf(stderr, "glibc pthread object maps failed: %d\n", result);
        return 1;
    }
    if (auto result = glibcError(); result != 0) {
        fprintf(stderr, "glibc dlerror semantics failed: %d\n", result);
        return 1;
    }
    if (glibcClose() != 0) {
        fprintf(stderr, "glibc dlclose contract failed\n");
        return 1;
    }

    auto* pci = stub_dlopen("libdlfcn-test-pci.so", RTLD_NOW | RTLD_LOCAL);

    if (!pci) {
        fprintf(stderr, "recursive load failed: %s\n", stub_dlerror());
        return 1;
    }
    if (!stub_dlsym(pci, "pci_system_init")) {
        fprintf(stderr, "libpciaccess lookup failed: %s\n", stub_dlerror());
        return 1;
    }

    std::unique_ptr<ElfImage> image;
    try {
        image.reset(ElfImage::loadElf("libdlfcn-test-vulkan.so", RTLD_NOW | RTLD_LOCAL));
    } catch (const std::exception& error) {
        fprintf(stderr, "load failed: %s\n", error.what());
        return 1;
    }

    auto enumerate = reinterpret_cast<EnumerateInstanceVersion>(image->lookup("vkEnumerateInstanceVersion"));

    if (!enumerate) {
        fprintf(stderr, "symbol lookup failed\n");
        return 1;
    }

    uint32_t version = 0;
    auto result = enumerate(&version);

    printf(
        "static libc provider: %zu symbols\n"
        "glibc dlopen/dlsym bridge: libc, libdl, pthread, factory, ELF, versions: ok\n"
        "recursive DT_NEEDED: libpciaccess -> libz: ok\n"
        "vkEnumerateInstanceVersion: result=%d version=%u.%u.%u\n",
        MUSL_SYMBOL_COUNT,
        result,
        version >> 22,
        (version >> 12) & 0x3ff,
        version & 0xfff
    );
    return result != 0;
}
