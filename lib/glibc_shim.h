#pragma once

#include <stddef.h>

#include <string_view>

namespace dyn {
    void* resolveGlibcSymbol(std::string_view name, std::string_view version, bool weak);
    void* resolveGlibcOverride(std::string_view name, std::string_view version);

    // The dlopen caller pool: one adapter instantiation per loaded image
    // that imports dlopen or dlmopen, handed out by the loader when the
    // import is relocated, so the bridge knows the issuing image without
    // inspecting the stack. Null past the pool's end.
    void* glibcDlopenCaller(size_t index);
    void* glibcDlmopenCaller(size_t index);
}
