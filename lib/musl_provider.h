#pragma once

#include "musl_symbols.h"

namespace dyn {
    struct MuslProvider {
        const MuslSymbol* symbols;
        size_t symbolCount;
        const MuslSymbol* overrides;
        size_t overrideCount;
    };

    MuslProvider muslProvider();
}
