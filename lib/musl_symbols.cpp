#include "musl_symbols.h"

using namespace dyn;

#include "musl_symbols.json.h"

MuslSymbols dyn::muslSymbols() {
    return {
        muslSymbolTable,
        sizeof(muslSymbolTable) / sizeof(muslSymbolTable[0]),
    };
}
