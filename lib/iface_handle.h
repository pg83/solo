#pragma once

#include <string_view>

namespace dyn {
    // A dlopen handle: anything stub_dlsym can look a symbol up in.
    struct IfaceHandle {
        enum class Kind {
            Provider,
            Image,
        };

        virtual Kind handleKind() const = 0;
        virtual void* lookup(std::string_view symbol) const = 0;
    };

    template <typename Y, typename X>
    Y* cast(X* x) noexcept {
        if (x && x->handleKind() == Y::kind) {
            return static_cast<Y*>(x);
        }
        return nullptr;
    }
}
