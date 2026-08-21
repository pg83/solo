#pragma once

#include <stddef.h>
#include <stdint.h>

// The static musl's TLS — embedded or the environment's, always static —
// opened to the loader. Compiled against musl's internal headers and linked
// against its hidden symbols: the same arrangement by which the loader
// already replaced musl's ldso.
//
// The offsets returned are thread-pointer-relative and signed the way the
// loader stores them: negative on x86-64, where static TLS sits below the
// thread pointer, positive on aarch64, where it sits above. Zero means the
// request does not fit and the module falls back to dynamic TLS.

#ifdef __cplusplus
extern "C" {
#endif

// Moves the main thread's pthread block onto a fresh allocation whose layout
// reserves a static TLS window next to the thread pointer, exactly what
// musl's own dynamic linker does between its stage 2 and stage 3 — the
// thread pointer is planted twice, and the second planting happens when the
// sizes are known. Runs from a constructor while the process is still
// single-threaded; idempotent; fails once other threads exist.
int soloTlsReplant(void);

// Places a module's TLS block in the window and registers its template with
// musl, so pthread_create's __copy_tls seeds the block in every thread
// created afterwards. The template is read at each thread's creation, so
// relocations applied to it are seen by later threads automatically.
intptr_t soloStaticTls(const void* image, size_t length, size_t size, size_t align);

// Places the main guest executable's TLS block at the ABI-mandated slot next
// to the thread pointer, where its local-exec offsets, burned into the
// instructions by the static linker, expect it. Only valid as the first
// placement, in a process whose own executable carries no TLS.
intptr_t soloExecutableTls(const void* image, size_t length, size_t size, size_t align);

#ifdef __cplusplus
}
#endif
