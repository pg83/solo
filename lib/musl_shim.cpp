#include "musl_shim.h"
#include "musl_symbols.h"

#include <string_view>
#include <unordered_map>

namespace {
    static const auto& muslProviders() {
        using Providers = std::unordered_map<std::string_view, void*>;
        static const auto* providers = [] {
            auto* result = new Providers();

            result->reserve(MUSL_SYMBOL_COUNT);
            for (size_t index = 0; index < MUSL_SYMBOL_COUNT; ++index) {
                const auto& symbol = MUSL_SYMBOLS[index];

                result->emplace(symbol.name, symbol.address);
            }

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
