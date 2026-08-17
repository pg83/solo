#pragma once

#include <stddef.h>

namespace dyn {
    struct MuslSymbol {
        const char* name;
        void* address;
    };

    struct MuslSymbols {
        const MuslSymbol* symbols;
        size_t count;
    };

    MuslSymbols muslSymbols();
}
