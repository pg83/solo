#pragma once

#include <stddef.h>

struct MuslSymbol {
    const char* name;
    void* address;
};

extern const MuslSymbol MUSL_SYMBOLS[];
extern const size_t MUSL_SYMBOL_COUNT;
