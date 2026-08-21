#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// The static musl's TLS — embedded or the environment's, always static —
// opened to the loader. The reservation itself is one link-time thread_local
// pad this file declares and never touches: musl sizes every thread's static
// TLS with it from process birth, the main thread included, so there is no
// startup call and no single-threaded moment. The loader carves guest blocks
// out of the pad and registers their templates with musl, whose own
// pthread_create machinery then seeds every thread created afterwards.
//
// The offsets returned are thread-pointer-relative and signed the way the
// loader stores them: negative on x86-64, where static TLS sits below the
// thread pointer, positive on aarch64, where it sits above. Zero means the
// request does not fit and the module falls back to dynamic TLS.

#ifdef __cplusplus
extern "C" {
#endif

// Reserves a block in the pad for a shared object's TLS, initial-exec
// demands and all; libraries consume the pad from its thread-pointer-distal
// end, leaving the ABI slot at the proximal end to the executable.
intptr_t soloStaticTls(size_t size, size_t align);

// Reserves the main guest executable's block at the ABI-mandated slot next
// to the thread pointer, where its local-exec offsets, burned into the
// instructions by the static linker, expect it. At most one executable, in
// a process whose PT_TLS is exactly the pad — a stray thread_local that
// unseats the pad from the thread pointer is refused here, loudly, through
// the loader; libraries loaded earlier are fine, the pool is exhausted only
// when the two ends meet.
intptr_t soloExecutableTls(const void* image, size_t size, size_t align);

// Registers a reserved block's template with musl, after relocations, so
// threads created later are seeded from relocated bytes. Threads already
// running keep zeroes: dlopen libraries with TLS before spawning threads
// that use them.
void soloTlsRegister(const void* image, size_t length, size_t size, intptr_t offset);

// Swaps the stream's polymorphic writer for one that issues a plain
// write(2) per segment. musl's __stdio_write hands writev a leading
// segment of buffered bytes that an unbuffered stream never has; procfs
// attribute files split a writev into one write per segment, the empty
// leading segment becomes a zero-length write, and the attribute parser
// answers EINVAL before any payload lands. glibc writes flat, and guests
// notice the difference. The bridge calls this when a guest turns a
// stream unbuffered.
void soloReplaceWriteFunc(FILE* file);

#ifdef __cplusplus
}
#endif
