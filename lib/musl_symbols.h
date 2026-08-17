#pragma once

#include <stddef.h>

struct MuslSymbol {
    const char* name;
    void* address;
};

struct MuslSymbols {
    const MuslSymbol* symbols;
    size_t count;
};

MuslSymbols muslSymbols();
