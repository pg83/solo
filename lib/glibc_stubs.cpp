#include "glibc_stubs.h"

#include "hash.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string_view>
#include <unordered_map>

namespace {
    struct GlibcStub {
        const char* name;
        const char* version;
        void* address;
        void* (*addressFunction)() noexcept;
    };

    [[noreturn]] static void abortStub(const char* name, const char* version) noexcept {
        fprintf(stderr, "glibc bridge: called unimplemented ABI %s@%s\n", name, version);
        abort();
    }

#include "glibc_symbols.json.h"

    struct Key {
        std::string_view name;
        std::string_view version;

        bool operator==(const Key&) const noexcept;
    };

    struct KeyHash {
        size_t operator()(const Key& key) const noexcept;
    };

    struct Provider {
        void* address;
        void* (*addressFunction)() noexcept;
    };

    static const auto& providers() {
        using Providers = std::unordered_map<Key, Provider, KeyHash>;

        static const auto* result = [] {
            auto* value = new Providers();

            value->reserve(sizeof(glibcStubTable) / sizeof(glibcStubTable[0]));

            for (const auto& stub : glibcStubTable) {
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

bool Key::operator==(const Key&) const noexcept = default;

size_t KeyHash::operator()(const Key& key) const noexcept {
    auto name = std::hash<std::string_view>()(key.name);
    auto version = std::hash<std::string_view>()(key.version);

    return splitMix64(name ^ version);
}

bool hasGlibcStub(std::string_view name, std::string_view version) {
    return providers().contains({name, version});
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
