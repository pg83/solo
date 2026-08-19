#pragma once

#include <string_view>

namespace dyn {
    // The resolver of last resort for images whose DT_NEEDED names bionic's
    // system libraries (libc.so, libm.so, libdl.so, liblog.so). Bionic's ABI
    // is unversioned, so everything goes by name: the bionic-specific
    // adapters first, then the glibc bridge's by-name providers (which end
    // in musl), and a loud refusal for the rest.
    void* resolveBionicSymbol(std::string_view name, bool weak);
}
