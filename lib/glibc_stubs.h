#pragma once

#include <string_view>

void* resolveGlibcStub(std::string_view name, std::string_view version);
