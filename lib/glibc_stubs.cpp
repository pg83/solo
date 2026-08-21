#include "glibc_stubs.h"

#include "elf_loader.h"

#include "hash.h"
#include "thread_tls.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string_view>
#include <unordered_map>

using namespace dyn;

namespace {
    struct GlibcStub {
        const char* name;
        const char* version;
        void* address;
        void* (*addressFunction)() noexcept;
        size_t objectSize;
    };

    [[noreturn]] static void abortStub(const char* name, const char* version) noexcept {
        fprintf(stderr, "glibc bridge: called unimplemented ABI %s@%s\n", name, version);
        abort();
    }

    // An unimplemented data object gets its own inaccessible pages: touching
    // it faults at the use instead of yielding silent zeroes far from the
    // cause, and the fault address identifies the object.
    static void* inaccessibleObject(size_t size) {
        auto* mapping = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapping == MAP_FAILED) {
            fprintf(stderr, "glibc bridge: cannot map an object stub\n");
            abort();
        }

        return mapping;
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
        bool inaccessible;
    };

    static const auto& providers() {
        using Providers = std::unordered_map<Key, Provider, KeyHash>;

        static const auto* result = [] {
            auto* value = new Providers();

            value->reserve(sizeof(glibcStubTable) / sizeof(glibcStubTable[0]));

            for (const auto& stub : glibcStubTable) {
                Provider provider{stub.address, stub.addressFunction, false};

                if (stub.objectSize) {
                    provider.address = inaccessibleObject(stub.objectSize);
                    provider.inaccessible = true;
                }
                value->emplace(Key{stub.name, stub.version}, provider);
            }

            return value;
        }();

        return *result;
    }

    static void report(const std::string_view& name, const std::string_view& version) noexcept {
        if (debugFlag("stubs")) {
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

bool dyn::hasGlibcStub(std::string_view name, std::string_view version) {
    return providers().contains({name, version});
}

std::vector<std::string_view> dyn::glibcSymbolVersions(std::string_view name) {
    std::vector<std::string_view> versions;

    for (const auto& stub : glibcStubTable) {
        if (name == std::string_view(stub.name)) {
            versions.push_back(stub.version);
        }
    }

    return versions;
}

void* dyn::resolveGlibcStub(std::string_view name, std::string_view version) {
    const auto& items = providers();

    if (auto item = items.find({name, version}); item != items.end()) {
        report(name, version);
        if (item->second.inaccessible) {
            fprintf(stderr, "glibc bridge: unimplemented data object %.*s@%.*s at %p is mapped inaccessible\n", static_cast<int>(name.size()), name.data(), static_cast<int>(version.size()), version.data(), item->second.address);
        }
        if (item->second.addressFunction) {
            return item->second.addressFunction();
        }

        return item->second.address;
    }

    return nullptr;
}
