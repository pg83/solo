#pragma once

#include <stddef.h>

#include <string_view>

namespace dyn {
    // Per-thread state of the loader: the thread-exit destructors loaded DSOs
    // register and their lazily allocated ELF TLS blocks. When the thread
    // exits, the destructors run first and the blocks are freed after, so a
    // destructor still sees its thread-local storage.
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

        static ThreadTls* current();
    };
}
