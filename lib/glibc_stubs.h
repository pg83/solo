#pragma once

#include <string_view>
#include <vector>

namespace dyn {
    bool hasGlibcStub(std::string_view name, std::string_view version);
    void* resolveGlibcStub(std::string_view name, std::string_view version);

    // Every version the platform's generated glibc inventory lists for the
    // name; empty when the platform's glibc does not export it.
    std::vector<std::string_view> glibcSymbolVersions(std::string_view name);
}
