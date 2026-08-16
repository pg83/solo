#pragma once

#include <string_view>

bool hasGlibcStub(std::string_view name, std::string_view version);
void* resolveGlibcStub(std::string_view name, std::string_view version);
