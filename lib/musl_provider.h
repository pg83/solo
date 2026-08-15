#pragma once

#include "musl_symbols.h"

struct MuslProvider {
    const MuslSymbol* symbols;
    size_t symbolCount;
    const MuslSymbol* overrides;
    size_t overrideCount;
};

MuslProvider muslProvider();
