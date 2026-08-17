#pragma once

#include <string_view>

namespace dyn {
    void* resolveGlibcSymbol(std::string_view name, std::string_view version, bool weak);
    void* resolveGlibcOverride(std::string_view name, std::string_view version);
}
