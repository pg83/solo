/* The static TLS window: how the loader gives guests thread-local storage at
 * fixed thread-pointer offsets without owning any TLS itself.
 *
 * musl already has everything needed. Every thread's static TLS is laid out
 * by __copy_tls from the module list in libc.tls_head, and the thread
 * pointer of the main thread is planted by __init_tp — twice in the dynamic
 * linker's own startup, the second time when the program's TLS sizes are
 * known. This file does the same from the static world: dyn::init(), called
 * at the top of main() by contract, re-plants the main thread onto an
 * allocation with a reserve next to the thread pointer, and the loader
 * registers each placed guest as one more tls_module, after which
 * pthread_create seeds every future thread by itself. The reserve is address
 * space, not memory: __copy_tls touches only the registered templates.
 */

#include "musl_tls.h"

/* musl's internal headers rely on annotations its own tree defines in
 * src/include/features.h; this file compiles outside that tree. */
#ifndef hidden
#define hidden __attribute__((__visibility__("hidden")))
#endif
#ifndef weak
#define weak __attribute__((__weak__))
#endif

#include "pthread_impl.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* The window's capacity beyond whatever the executable's own TLS occupies,
 * and the thread pointer's guaranteed alignment. One megabyte of address
 * space per thread costs pages only where templates are actually copied;
 * liblsan's 56K initial-exec block, the largest real demand seen so far,
 * fits with room to spare. */
#define SOLO_TLS_RESERVE (1024 * 1024)
#define SOLO_TLS_MODULES 64
#define SOLO_TLS_ALIGN 64

static struct tls_module soloModules[SOLO_TLS_MODULES];
static size_t soloModuleCount;

/* Occupied bytes of the module span, measured from the thread pointer away
 * from it, and the span's capacity. */
static size_t soloExtent;
static size_t soloCapacity;
static int soloReplanted;

static size_t moduleEnd(const struct tls_module* module) {
#ifdef TLS_ABOVE_TP
	return module->offset + module->size;
#else
	return module->offset;
#endif
}

int soloTlsReplant(void) {
	if (soloReplanted) {
		return 0;
	}
	if (libc.threads_minus_1) {
		return -1;
	}

	for (struct tls_module* module = libc.tls_head; module; module = module->next) {
		if (moduleEnd(module) > soloExtent) {
			soloExtent = moduleEnd(module);
		}
	}
	soloCapacity = soloExtent + SOLO_TLS_RESERVE;

	size_t size = libc.tls_size + SOLO_TLS_RESERVE
		+ SOLO_TLS_MODULES * sizeof(uintptr_t) + SOLO_TLS_ALIGN;
	unsigned char* block = calloc(size, 1);

	if (!block) {
		return -1;
	}

	libc.tls_size = size;
	if (libc.tls_align < SOLO_TLS_ALIGN) {
		libc.tls_align = SOLO_TLS_ALIGN;
	}

	/* The move itself: lay out the new block, carry the live pthread state
	 * over, and re-aim the self-referential fields. Everything else that
	 * points at the thread — the kernel's tid address, the tsd array — is
	 * either global or carried by the copy. Signals stay blocked across the
	 * instant when the old and the new thread pointer disagree. */
	sigset_t all;
	sigset_t previous;

	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &previous);

	pthread_t self = __pthread_self();
	pthread_t fresh = __copy_tls(block);
	uintptr_t* dtv = fresh->dtv;

	memcpy(fresh, self, sizeof(struct pthread));
	fresh->self = fresh;
	fresh->dtv = dtv;
	fresh->prev = fresh->next = fresh;
	fresh->robust_list.head = &fresh->robust_list.head;

	int planted = __set_thread_area(TP_ADJ(fresh));

	pthread_sigmask(SIG_SETMASK, &previous, 0);
	if (planted < 0) {
		return -1;
	}
	soloReplanted = 1;

	return 0;
}

static intptr_t registerModule(const void* image, size_t length, size_t size, size_t offset) {
	struct tls_module* module = &soloModules[soloModuleCount++];

	module->image = (void*)image;
	module->len = length;
	module->size = size;
	module->align = SOLO_TLS_ALIGN;
	module->offset = offset;
	module->next = 0;

	/* Appended at the tail: a module's dtv slot is its list position, and
	 * the slots of already-registered modules must not shift. */
	struct tls_module** tail = &libc.tls_head;

	while (*tail) {
		tail = &(*tail)->next;
	}
	*tail = module;
	libc.tls_cnt++;

#ifdef TLS_ABOVE_TP
	return (intptr_t)offset;
#else
	return -(intptr_t)offset;
#endif
}

intptr_t soloStaticTls(const void* image, size_t length, size_t size, size_t align) {
	if (soloTlsReplant() || align > SOLO_TLS_ALIGN || soloModuleCount == SOLO_TLS_MODULES) {
		return 0;
	}
	if (align < sizeof(uintptr_t)) {
		align = sizeof(uintptr_t);
	}

#ifdef TLS_ABOVE_TP
	/* Blocks sit at TP + offset; the gap above the thread pointer belongs
	 * to the ABI's TCB. */
	size_t start = soloExtent > (size_t)GAP_ABOVE_TP ? soloExtent : (size_t)GAP_ABOVE_TP;
	size_t offset = (start + align - 1) & -align;
	size_t end = offset + size;
#else
	/* Blocks sit at TP - offset, and the offset itself must carry the
	 * block's alignment. */
	size_t offset = (soloExtent + size + align - 1) & -align;
	size_t end = offset;
#endif

	if (end > soloCapacity) {
		return 0;
	}
	soloExtent = end;

	return registerModule(image, length, size, offset);
}

intptr_t soloExecutableTls(const void* image, size_t length, size_t size, size_t align) {
	if (soloTlsReplant() || align > SOLO_TLS_ALIGN || soloModuleCount == SOLO_TLS_MODULES) {
		return 0;
	}
	/* The ABI slot is adjacent to the thread pointer; anything already
	 * placed there — the process's own TLS, an earlier guest — occupies it
	 * for good. */
	if (libc.tls_head) {
		return 0;
	}

	/* musl's own formula for the main program's block, congruence with the
	 * template's address included; the static linker burned the matching
	 * offsets into the guest's instructions. */
#ifdef TLS_ABOVE_TP
	size_t offset = GAP_ABOVE_TP;
	offset += (-(size_t)GAP_ABOVE_TP + (uintptr_t)image) & (align - 1);
	size_t end = offset + size;
#else
	size += (-size - (uintptr_t)image) & (align - 1);
	size_t offset = size;
	size_t end = offset;
#endif

	if (end > soloCapacity) {
		return 0;
	}
	if (end > soloExtent) {
		soloExtent = end;
	}

	return registerModule(image, length, size, offset);
}

