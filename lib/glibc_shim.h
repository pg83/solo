#pragma once

#include <string_view>

void* resolveGlibcSymbol(const std::string_view& name, const std::string_view& version, bool weak);
