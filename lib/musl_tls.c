/* The static TLS pad: how the loader gives guests thread-local storage at
 * fixed thread-pointer offsets without moving anything at runtime.
 *
 * The pad is one ordinary thread_local this file never reads or writes. Its
 * only job is to make musl reserve the bytes: __init_tls sizes the main
 * thread's static TLS with it before any of our code runs, and pthread_create
 * sizes every later thread's the same way — so a span of donated memory sits
 * next to every thread's thread pointer from birth. All zeroes in .tbss: no
 * file bytes, no pages until someone writes.
 *
 * The loader carves guest blocks out of that span. On x86-64 the pad is
 * solo's whole PT_TLS and musl's own layout puts it flush against the thread
 * pointer, which is exactly where a guest executable's local-exec offsets
 * point; libraries consume the pad from the opposite end, so the ABI slot
 * stays free for the executable wherever in the load order it arrives, and
 * the pool is exhausted only when the two watermarks meet. Each placed block
 * is then registered
 * as one more tls_module in libc.tls_head, and musl's __copy_tls seeds it in
 * every thread created afterwards, reading the mapped template after
 * relocations by construction. libc.tls_size grows by one pointer per
 * module, keeping the dtv slots __copy_tls writes for the new entries inside
 * every newborn thread's allocation; threads that already exist are never
 * revisited and never see the new dtv entries.
 */

#include "musl_tls.h"

/* musl's internal headers rely on annotations its own tree defines in
 * src/include/features.h; this file compiles outside that tree. The header
 * itself comes by relative path, not by include directory: musl's private
 * headers shadow public names, so their directory must never appear on the
 * include path the library's C++ sources share. */
#ifndef hidden
#define hidden __attribute__((__visibility__("hidden")))
#endif
#ifndef weak
#define weak __attribute__((__weak__))
#endif

#include "../ext/musl/src/internal/libc.h"

/* The donated span and the ceiling on a block's alignment; the pad's own
 * alignment is what makes every thread pointer a multiple of it. liblsan's
 * 56K initial-exec block, the largest real demand seen so far, fits with
 * room to spare, and .tbss address space is all this costs. */
#define SOLO_TLS_PAD (1024 * 1024)
#define SOLO_TLS_ALIGN 64
#define SOLO_TLS_MODULES 64

/* The aarch64 TCB: two pointers at the thread pointer, blocks above. */
#define SOLO_TLS_GAP 16

static _Thread_local unsigned char soloTlsPad[SOLO_TLS_PAD] __attribute__((aligned(SOLO_TLS_ALIGN)));

static struct tls_module soloModules[SOLO_TLS_MODULES];
static size_t soloModuleCount;

/* Two watermarks growing toward each other: the executable owns the pad's
 * thread-pointer-proximal end — the ABI slot — whenever in the load order it
 * arrives, and libraries consume the pad from the distal end. The pool is
 * exhausted when they meet. */
static size_t soloExecutableExtent;
static size_t soloLibraryExtent;
static int soloExecutablePlaced;
static size_t soloReserved;

static uintptr_t threadPointer(void) {
	uintptr_t pointer;

#if defined(__x86_64__)
	__asm__("mov %%fs:0, %0" : "=r"(pointer));
#elif defined(__aarch64__)
	__asm__("mrs %0, tpidr_el0" : "=r"(pointer));
#endif

	return pointer;
}

/* The pad's thread-pointer-relative offset: a process-wide constant, the
 * same in every thread, discovered from whichever thread reserves first.
 * All reservations run under the loader's lock. */
static intptr_t padOffset(void) {
	static intptr_t offset;
	static int known;

	if (!known) {
		offset = (intptr_t)soloTlsPad - (intptr_t)threadPointer();
		known = 1;
	}

	return offset;
}

intptr_t soloStaticTls(size_t size, size_t align) {
	if (align > SOLO_TLS_ALIGN || soloReserved == SOLO_TLS_MODULES) {
		return 0;
	}
	if (align < sizeof(uintptr_t)) {
		align = sizeof(uintptr_t);
	}

	/* Libraries pack from the pad's thread-pointer-distal end, whichever
	 * side that is on the architecture; both ends are aligned relative to
	 * the thread pointer by the pad itself, so either direction hands out
	 * aligned blocks. */
#if defined(__x86_64__)
	/* Distal end = the pad's start; blocks pack upward, toward the thread
	 * pointer. */
	size_t start = (soloLibraryExtent + align - 1) & -align;
	size_t extent = start + size;
	intptr_t offset = padOffset() + (intptr_t)start;
#else
	/* Distal end = the pad's end; blocks pack downward, the offset itself
	 * carrying the alignment. */
	size_t extent = (soloLibraryExtent + size + align - 1) & -align;
	intptr_t offset = padOffset() + SOLO_TLS_PAD - (intptr_t)extent;
#endif

	if (extent + soloExecutableExtent > SOLO_TLS_PAD) {
		return 0;
	}
	soloLibraryExtent = extent;
	soloReserved++;

	return offset;
}

intptr_t soloExecutableTls(const void* image, size_t size, size_t align) {
	if (align > SOLO_TLS_ALIGN || soloReserved == SOLO_TLS_MODULES || soloExecutablePlaced) {
		return 0;
	}

	/* musl's own formula for the main program's block, congruence with the
	 * template's address included; the static linker burned the matching
	 * offsets into the guest's instructions. */
#if defined(__x86_64__)
	/* The pad must end exactly at the thread pointer — true when it is the
	 * executable's only thread_local; a stray one unseats it. */
	if (padOffset() + SOLO_TLS_PAD != 0) {
		return 0;
	}

	size += (-size - (uintptr_t)image) & (align - 1);

	if (size + soloLibraryExtent > SOLO_TLS_PAD) {
		return 0;
	}
	soloExecutableExtent = size;
	soloExecutablePlaced = 1;
	soloReserved++;

	return -(intptr_t)size;
#else
	/* The pad starts where the TCB gap ends, rounded to the pad's own
	 * alignment; the guest's block may begin inside that rounding gap,
	 * which exists, zeroed, in every thread's allocation. */
	if (padOffset() != (intptr_t)((SOLO_TLS_GAP + SOLO_TLS_ALIGN - 1) & -(size_t)SOLO_TLS_ALIGN)) {
		return 0;
	}

	size_t offset = SOLO_TLS_GAP;
	offset += (-(size_t)SOLO_TLS_GAP + (uintptr_t)image) & (align - 1);

	size_t extent = 0;

	if (offset + size > (size_t)padOffset()) {
		extent = offset + size - (size_t)padOffset();
	}
	if (extent + soloLibraryExtent > SOLO_TLS_PAD) {
		return 0;
	}
	soloExecutableExtent = extent;
	soloExecutablePlaced = 1;
	soloReserved++;

	return (intptr_t)offset;
#endif
}

void soloTlsRegister(const void* image, size_t length, size_t size, intptr_t offset) {
	if (soloModuleCount == SOLO_TLS_MODULES) {
		return;
	}

	struct tls_module* module = &soloModules[soloModuleCount++];

	module->image = (void*)image;
	module->len = length;
	module->size = size;
	module->align = SOLO_TLS_ALIGN;
#if defined(__x86_64__)
	module->offset = (size_t)-offset;
#else
	module->offset = (size_t)offset;
#endif
	module->next = 0;

	/* Appended at the tail: a module's dtv slot is its list position, and
	 * the slots of already-registered modules must not shift. */
	struct tls_module** tail = &libc.tls_head;

	while (*tail) {
		tail = &(*tail)->next;
	}
	*tail = module;
	libc.tls_cnt++;
	/* One more dtv slot in every thread created from here on. */
	libc.tls_size += sizeof(uintptr_t);
}
