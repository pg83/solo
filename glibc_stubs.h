#pragma once

#include <string_view>

void* resolveGlibcStub(const std::string_view& name, const std::string_view& version);
