#pragma once

#include <string_view>

namespace dyn {
    // A dlopen handle: anything stub_dlsym can look a symbol up in.
    struct IfaceHandle {
        virtual void* lookup(std::string_view symbol) const = 0;
    };
}
