#pragma once

#include <string_view>

void* resolveGlibcSymbol(std::string_view name, std::string_view version, bool weak);
void* resolveGlibcOverride(std::string_view name, std::string_view version);
