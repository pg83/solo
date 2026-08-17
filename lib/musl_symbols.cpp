#include "musl_symbols.h"

namespace {
#include "musl_symbols.json.h"
}

MuslSymbols muslSymbols() {
    return {
        muslSymbolTable,
        sizeof(muslSymbolTable) / sizeof(muslSymbolTable[0]),
    };
}
