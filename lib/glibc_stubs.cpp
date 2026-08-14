#include "glibc_stubs.h"

#include "hash.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string_view>
#include <unordered_map>

namespace {
    [[noreturn]] void abortStub(const char* name, const char* version) noexcept {
        fprintf(stderr, "glibc bridge: called unimplemented ABI %s@%s\n", name, version);
        abort();
    }

#define GLIBC_JOIN_(LEFT, RIGHT) LEFT##RIGHT
#define GLIBC_JOIN(LEFT, RIGHT) GLIBC_JOIN_(LEFT, RIGHT)
#define GLIBC_FUNCTION_STUB(ID, NAME, VERSION, SIZE)                 \
    [[noreturn]] void GLIBC_JOIN(glibcFunctionStub, ID)() noexcept { \
        abortStub(NAME, VERSION);                                    \
    }
#define GLIBC_OBJECT_STUB(ID, NAME, VERSION, SIZE) alignas(max_align_t) unsigned char GLIBC_JOIN(glibcObjectStub, ID)[SIZE ? SIZE : 1] = {};
#define GLIBC_TLS_STUB(ID, NAME, VERSION, SIZE)                                                         \
    alignas(max_align_t) thread_local unsigned char GLIBC_JOIN(glibcTlsStub, ID)[SIZE ? SIZE : 1] = {}; \
    void* GLIBC_JOIN(glibcTlsStubAddress, ID)() noexcept {                                              \
        return GLIBC_JOIN(glibcTlsStub, ID);                                                            \
    }
#include "glibc_stubs.inc"
#undef GLIBC_FUNCTION_STUB
#undef GLIBC_OBJECT_STUB
#undef GLIBC_TLS_STUB

    struct Stub {
        const char* name;
        const char* version;
        void* address;
        void* (*addressFunction)() noexcept;
    };

    const Stub STUBS[] = {
#define GLIBC_FUNCTION_STUB(ID, NAME, VERSION, SIZE) {NAME, VERSION, reinterpret_cast<void*>(GLIBC_JOIN(glibcFunctionStub, ID)), nullptr},
#define GLIBC_OBJECT_STUB(ID, NAME, VERSION, SIZE) {NAME, VERSION, GLIBC_JOIN(glibcObjectStub, ID), nullptr},
#define GLIBC_TLS_STUB(ID, NAME, VERSION, SIZE) {NAME, VERSION, nullptr, GLIBC_JOIN(glibcTlsStubAddress, ID)},
#include "glibc_stubs.inc"
#undef GLIBC_FUNCTION_STUB
#undef GLIBC_OBJECT_STUB
#undef GLIBC_TLS_STUB
    };

    struct Key {
        std::string_view name;
        std::string_view version;

        bool operator==(const Key&) const noexcept = default;
    };

    struct KeyHash {
        size_t operator()(const Key& key) const noexcept {
            auto name = std::hash<std::string_view>()(key.name);
            auto version = std::hash<std::string_view>()(key.version);

            return splitMix64(name ^ version);
        }
    };

    struct Provider {
        void* address;
        void* (*addressFunction)() noexcept;
    };

    const auto& providers() {
        using Providers = std::unordered_map<Key, Provider, KeyHash>;
        static const auto* result = [] {
            auto* value = new Providers();

            value->reserve(sizeof(STUBS) / sizeof(STUBS[0]));
            for (const auto& stub : STUBS) {
                value->emplace(Key{stub.name, stub.version}, Provider{stub.address, stub.addressFunction});
            }

            return value;
        }();

        return *result;
    }

    static void report(const std::string_view& name, const std::string_view& version) noexcept {
        if (getenv("DL_GLIBC_STUB_DEBUG")) {
            fprintf(stderr, "glibc bridge: resolved fallback %.*s@%.*s\n", static_cast<int>(name.size()), name.data(), static_cast<int>(version.size()), version.data());
        }
    }
}

void* resolveGlibcStub(std::string_view name, std::string_view version) {
    const auto& items = providers();

    if (auto item = items.find({name, version}); item != items.end()) {
        report(name, version);
        if (item->second.addressFunction) {
            return item->second.addressFunction();
        }

        return item->second.address;
    }

    return nullptr;
}
