#pragma once

// Where the loader gets the bytes of an image. Internal to the loader; the
// bundle's public entry points are soloHasBundle() and soloBundleMain() in
// dlfcn.h, which is the whole API a stub needs.
//
// A bundle's payload sits after the stub's own ELF: a trailer at the very
// end of the file points at an index, and the index names members that
// start on 64 KiB boundaries. Because they are aligned, the loader maps a
// member straight out of the stub's file at an offset — nothing is
// unpacked, the pages come from the one file's page cache, and
// /proc/self/exe keeps naming the program the user actually ran.

#include <sys/types.h>

#include <optional>
#include <string>
#include <string_view>

namespace dyn {
    // An ordinary image is a path and owns the descriptor the loader opens
    // for it; a bundled one carries the descriptor of the executable it was
    // appended to and a page-aligned base to read and map at. The path is
    // the image's identity either way — link_map, dladdr, and ldd report it.
    struct ImageSource {
        std::string path;
        int descriptor = -1;
        off_t base = 0;
    };

    // The bundled member of this name, if this executable carries one.
    // Names are matched exactly as a guest's DT_NEEDED spells them, so the
    // packer records an entry per soname a member answers to.
    std::optional<ImageSource> bundleMember(std::string_view name);
}
