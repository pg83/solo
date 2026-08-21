#pragma once

#include <stddef.h>

#include <string_view>

namespace dyn {
    // Per-thread state of the loader and the bridges, behind one door. The
    // backing is a pthread key — the embedded musl keeps key values in its
    // pthread structure, so none of this puts a single byte into the
    // executable's own PT_TLS, which must hold exactly the static TLS pad
    // and nothing else. When the thread exits, the destructors loaded DSOs
    // registered run first and the storage is freed after, so a destructor
    // still sees its thread-local state.
    struct ThreadTls {
        virtual void registerDtor(void (*function)(void*), void* argument) = 0;

        // The slot holding the TLS block of the module; grows on demand. The
        // caller stores memory that free() can release.
        virtual void** tlsBlock(size_t module) = 0;

        // The pending dlerror() message of the thread. take() consumes it,
        // and the returned text stays valid until the next take, as dlerror()
        // requires.
        virtual void setDlError(std::string_view error) = 0;
        virtual void clearDlError() = 0;
        virtual char* takeDlError() = 0;

        // The glibc inventory's TLS-kind symbols (errno@GLIBC_PRIVATE and
        // friends): per-thread zeroed storage keyed by the symbol's inventory
        // index, alive until the thread's destructors have run.
        virtual void* tlsStub(size_t index, size_t size) = 0;

        // The nftw adapter's per-thread callback slot, held across the walk.
        virtual void** nftwCallback() = 0;

        static ThreadTls* current();
    };
}
