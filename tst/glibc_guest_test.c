/* A whole glibc executable for `solo run`: linked against the sysroot's
 * Scrt1.o and libc.so.6, so its _start is glibc's own crt and its startup
 * goes through the bridge's __libc_start_main. Self-declared prototypes keep
 * it independent of the compiling host's headers, like glibc_test.c. The
 * stdout and environ references compile to copy relocations on toolchains
 * that favor direct access in PIE code, and to GOT loads elsewhere — both
 * paths must work. */

typedef struct guest_file FILE;

extern FILE* stdout;
extern FILE* stderr;
extern char** environ;
extern int optind;

int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
char* getenv(const char* name);
int __posix_getopt(int argc, char* const argv[], const char* options);
void exit(int status);
/* atexit itself lives in glibc's libc_nonshared.a, which a -nostdlib link
 * has no business pulling in; the underlying exported call serves. */
int __cxa_atexit(void (*function)(void*), void* argument, void* handle);

/* Old symbol versions, as a binary linked against an older glibc imports
 * them: each must reach its adapter, not a fail-loud stub. */
typedef struct {
    unsigned long gl_pathc;
    char** gl_pathv;
    unsigned long gl_offs;
    int gl_flags;
    void* gl_alternatives[5];
} guest_glob_t;

struct guest_timespec {
    long tv_sec;
    long tv_nsec;
};

int guest_glob64_old(const char* pattern, int flags, int (*failed)(const char*, int), guest_glob_t* result);
void globfree64(guest_glob_t* result);
int guest_clocklock_old(void* mutex, int clock, const struct guest_timespec* deadline);
int pthread_mutex_unlock(void* mutex);
int clock_gettime(int clock, struct guest_timespec* now);

#if defined(__x86_64__)
__asm__(".symver guest_glob64_old, glob64@GLIBC_2.2.5");
#elif defined(__aarch64__)
__asm__(".symver guest_glob64_old, glob64@GLIBC_2.17");
#endif
/* libpthread's version, before glibc 2.34 moved the call into libc. */
__asm__(".symver guest_clocklock_old, pthread_mutex_clocklock@GLIBC_2.30");

static int guest_old_versions_check(void) {
    guest_glob_t found = {0};
    int matches = guest_glob64_old("/", 0, 0, &found) == 0 ? (int)found.gl_pathc : -1;

    if (matches >= 0) {
        globfree64(&found);
    }

    /* A default mutex is all zeroes, the size of the largest pthread_mutex_t. */
    _Alignas(16) unsigned char mutex[64] = {0};
    struct guest_timespec deadline;

    if (clock_gettime(1, &deadline)) {
        printf("guest old versions clock_gettime failed\n");
        return 0;
    }
    deadline.tv_sec += 1;

    int locked = guest_clocklock_old(mutex, 1, &deadline);
    int unlocked = locked ? -1 : pthread_mutex_unlock(mutex);

    printf("guest old versions glob64=%d clocklock=%d\n", matches, locked);
    return matches == 1 && !locked && !unlocked;
}

void* mmap(void* address, unsigned long length, int protection, int flags, int fd, long offset);
int mprotect(void* address, unsigned long length, int protection);
int munmap(void* address, unsigned long length);

typedef unsigned long guest_pthread_t;
int pthread_create(guest_pthread_t* thread, const void* attributes, void* (*function)(void*), void* argument);
int pthread_join(guest_pthread_t thread, void** result);

void* malloc(unsigned long size);
void free(void* pointer);
char* realpath(const char* path, char* resolved);
int asprintf(char** result, const char* format, ...);

/* One heap for the whole process, whichever allocator serves it: the guest
 * frees what musl allocated on its behalf, and what another thread
 * allocated. */
static void* guest_heap_thread(void* argument) {
    free(argument);
    return malloc(24);
}

static void guest_heap_check(void) {
    char* resolved = realpath("/", 0);
    char* formatted = 0;
    int shared = resolved && asprintf(&formatted, "%s", "heap") > 0;

    free(resolved);
    free(formatted);

    guest_pthread_t thread;
    void* returned = 0;

    shared = shared && !pthread_create(&thread, 0, guest_heap_thread, malloc(48)) && !pthread_join(thread, &returned);
    free(returned);
    printf("guest heap %s\n", shared ? "shared" : "split");
}

/* The executable's own TLS: the static linker burns these offsets into the
 * instructions against the ABI's thread-pointer layout, and the loader must
 * have put the blocks exactly there — in the main thread and in every thread
 * the runtime creates, each with its own copy of the template. */
__thread long guest_tls_data = 0x51106011;
__thread long guest_tls_bss[8];

static void* guest_thread(void* argument) {
    (void)argument;
    printf("guest thread tls=%lx bss=%ld\n", guest_tls_data, guest_tls_bss[0]);
    guest_tls_data = 7;
    return 0;
}

/* The unwinder as LuaJIT drives it: its own personality reads the context
 * _Unwind_RaiseException hands it, and the exception crosses a frame of
 * generated code whose unwind info went through libgcc's whole-section
 * __register_frame. Every one of those calls must reach one unwinder. */
typedef unsigned long guest_uword;

struct guest_unwind_exception {
    unsigned long long exception_class;
    void (*exception_cleanup)(int reason, struct guest_unwind_exception* exception);
    guest_uword private_1;
    guest_uword private_2;
} __attribute__((aligned(16)));

int _Unwind_RaiseException(struct guest_unwind_exception* exception);
guest_uword _Unwind_GetCFA(void* context);
struct guest_dwarf_bases {
    guest_uword text;
    guest_uword data;
    guest_uword function;
};
const void* _Unwind_Find_FDE(const void* pc, struct guest_dwarf_bases* bases);
void* _Unwind_FindEnclosingFunction(void* pc);
void __register_frame(const void* section);
void __deregister_frame(const void* section);

static int guest_personality_calls;
static guest_uword guest_personality_cfa;

static int guest_personality(int version, int actions, unsigned long long exception_class, struct guest_unwind_exception* exception, void* context) {
    (void)version;
    (void)actions;
    (void)exception_class;
    (void)exception;
    if (guest_personality_calls++ == 0) {
        guest_personality_cfa = _Unwind_GetCFA(context);
    }
    /* _URC_CONTINUE_UNWIND: no handler here, keep searching. */
    return 8;
}

/* DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4 reads the personality
 * through this cell, the way compilers spell DW.ref.__gxx_personality_v0. */
__attribute__((used)) static void* const guest_personality_cell = (void*)guest_personality;

/* The generated code calls the function in the first argument register
 * from a frame with its own CFA rule. */
#if defined(__x86_64__)
static const unsigned char guest_jit_code[] = {
    0x48, 0x83, 0xec, 0x08, /* sub $8, %rsp */
    0xff, 0xd7, /* call *%rdi */
    0x48, 0x83, 0xc4, 0x08, /* add $8, %rsp */
    0xc3, /* ret */
};
static const unsigned char guest_cie_program[] = {
    0x0c, 0x07, 0x08, /* DW_CFA_def_cfa: rsp + 8 */
    0x90, 0x01, /* DW_CFA_offset: rip at cfa - 8 */
};
static const unsigned char guest_fde_program[] = {
    0x44, /* DW_CFA_advance_loc: 4 */
    0x0e, 0x10, /* DW_CFA_def_cfa_offset: 16 */
};
enum { guest_code_align = 1, guest_return_column = 16 };
#elif defined(__aarch64__)
static const unsigned int guest_jit_code[] = {
    0xa9bf7bfd, /* stp x29, x30, [sp, #-16]! */
    0x910003fd, /* mov x29, sp */
    0xd63f0000, /* blr x0 */
    0xa8c17bfd, /* ldp x29, x30, [sp], #16 */
    0xd65f03c0, /* ret */
};
static const unsigned char guest_cie_program[] = {
    0x0c, 0x1f, 0x00, /* DW_CFA_def_cfa: sp + 0 */
};
static const unsigned char guest_fde_program[] = {
    0x41, /* DW_CFA_advance_loc: 1 instruction */
    0x0e, 0x10, /* DW_CFA_def_cfa_offset: 16 */
    0x9d, 0x02, /* DW_CFA_offset: x29 at cfa - 16 */
    0x9e, 0x01, /* DW_CFA_offset: x30 at cfa - 8 */
};
enum { guest_code_align = 4, guest_return_column = 30 };
#endif

static void guest_put32(unsigned char* at, unsigned int value) {
    for (int index = 0; index < 4; ++index) {
        at[index] = (unsigned char)(value >> (8 * index));
    }
}

static unsigned char* guest_put_bytes(unsigned char* at, const unsigned char* bytes, unsigned long count) {
    for (unsigned long index = 0; index < count; ++index) {
        *at++ = bytes[index];
    }
    return at;
}

enum { guest_jit_count = 2, guest_jit_stride = 64, guest_jit_mapping_size = 4096 };

/* One CIE shared by two FDEs, then the zero terminator. Both frames must
 * register and deregister through libgcc's whole-section API. The section
 * shares the code's mapping, as pc_begin is a 32-bit pc-relative offset. */
static void guest_build_eh_frame(unsigned char* section, const unsigned char* code, const void** frames) {
    unsigned char* cie = section;
    unsigned char* at = cie + 4;

    guest_put32(at, 0);
    at += 4;
    *at++ = 1;
    *at++ = 'z';
    *at++ = 'R';
    *at++ = 0;
    *at++ = guest_code_align;
    *at++ = 0x78; /* data alignment -8 */
    *at++ = guest_return_column;
    *at++ = 1;
    *at++ = 0x1b; /* FDE pointers: DW_EH_PE_pcrel | DW_EH_PE_sdata4 */
    at = guest_put_bytes(at, guest_cie_program, sizeof(guest_cie_program));
    while ((at - cie) % 8) {
        *at++ = 0; /* DW_CFA_nop */
    }
    guest_put32(cie, (unsigned int)(at - cie - 4));

    for (int index = 0; index < guest_jit_count; ++index) {
        unsigned char* fde = at;

        frames[index] = fde;
        at = fde + 4;
        guest_put32(at, (unsigned int)(at - cie));
        at += 4;
        guest_put32(at, (unsigned int)(code + index * guest_jit_stride - at));
        at += 4;
        guest_put32(at, sizeof(guest_jit_code));
        at += 4;
        *at++ = 0;
        at = guest_put_bytes(at, guest_fde_program, sizeof(guest_fde_program));
        while ((at - fde) % 8) {
            *at++ = 0;
        }
        guest_put32(fde, (unsigned int)(at - fde - 4));
    }
    guest_put32(at, 0);
}

/* The cache maintenance __builtin___clear_cache would call into libgcc for,
 * which a -nostdlib link does not have. */
static void guest_sync_code(unsigned char* code, unsigned long size) {
#if defined(__aarch64__)
    for (unsigned long offset = 0; offset < size; offset += 4) {
        __asm__ volatile("dc cvau, %0" ::"r"(code + offset) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (unsigned long offset = 0; offset < size; offset += 4) {
        __asm__ volatile("ic ivau, %0" ::"r"(code + offset) : "memory");
    }
    __asm__ volatile("dsb ish\n\tisb" ::: "memory");
#else
    (void)code;
    (void)size;
#endif
}

static void guest_raise(void) {
    static struct guest_unwind_exception exception = {0x534f4c4f54455354ull, 0, 0, 0};

    /* End of stack once the search passes main: nothing catches it. */
    _Unwind_RaiseException(&exception);
}

/* The frame whose personality is the guest's own. */
__attribute__((noinline)) static void guest_unwind_frame(void (*jit)(void (*)(void)), volatile guest_uword* anchor) {
    __asm__ volatile(".cfi_personality 0x9b, guest_personality_cell");
    volatile char local = 0;

    *anchor = (guest_uword)&local;
    jit(guest_raise);
    /* Keeps the call from becoming a tail call that drops this frame. */
    __asm__ volatile("" ::: "memory");
}

static int guest_unwind_check(void) {
    unsigned char* code = mmap(0, guest_jit_mapping_size, 1 | 2, 2 | 0x20, -1, 0);

    if (code == (unsigned char*)-1) {
        printf("guest unwind mmap failed\n");
        return 0;
    }
    for (int index = 0; index < guest_jit_count; ++index) {
        unsigned char* entry = code + index * guest_jit_stride;

        guest_put_bytes(entry, (const unsigned char*)guest_jit_code, sizeof(guest_jit_code));
        guest_sync_code(entry, sizeof(guest_jit_code));
    }

    unsigned char* section = code + 256;
    const void* frames[guest_jit_count];

    guest_build_eh_frame(section, code, frames);
    if (mprotect(code, guest_jit_mapping_size, 1 | 4)) {
        printf("guest unwind mprotect failed\n");
        munmap(code, guest_jit_mapping_size);
        return 0;
    }

    int called = 1;
    int sane = 1;
    int registered = 1;
    int deregistered = 1;

    for (int cycle = 0; cycle < 2; ++cycle) {
        __register_frame(section);
        for (int index = 0; index < guest_jit_count; ++index) {
            unsigned char* entry = code + index * guest_jit_stride;
            struct guest_dwarf_bases bases = {0, 0, 0};
            volatile guest_uword anchor = 0;

            registered &= _Unwind_Find_FDE(entry + 4, &bases) == frames[index];
            registered &= bases.function == (guest_uword)entry;
            registered &= _Unwind_FindEnclosingFunction(entry + 4) == entry;
            guest_personality_calls = 0;
            guest_personality_cfa = 0;
            guest_unwind_frame((void (*)(void (*)(void)))entry, &anchor);
            called &= guest_personality_calls != 0;
            /* Inside a personality the CFA is the examined frame's SP at
             * its call site, just below guest_unwind_frame's locals. */
            sane &= guest_personality_cfa <= anchor && anchor - guest_personality_cfa < 4096;
        }
        __deregister_frame(section);
        for (int index = 0; index < guest_jit_count; ++index) {
            unsigned char* entry = code + index * guest_jit_stride;
            struct guest_dwarf_bases bases = {0, 0, 0};

            deregistered &= _Unwind_Find_FDE(entry + 4, &bases) == 0;
            deregistered &= _Unwind_FindEnclosingFunction(entry + 4) == 0;
        }
    }

    int released = munmap(code, guest_jit_mapping_size) == 0;

    printf("guest unwind personality=%s cfa=%s\n", called ? "called" : "skipped", sane ? "ok" : "bad");
    printf("guest unwind frames=%d registration=%s deregistration=%s\n", guest_jit_count, registered ? "ok" : "bad", deregistered ? "ok" : "bad");
    return called && sane && registered && deregistered && released;
}

static int guest_constructed;

__attribute__((constructor)) static void guest_constructor(void) {
    guest_constructed = 1;
    printf("guest init\n");
    if (getenv("SOLO_EXIT_IN_INIT")) {
        exit(43);
    }
}

/* Finalizers run at exit only for images whose initializers ran: ldd's
 * trace mode maps the guest without initializing it. */
__attribute__((destructor)) static void guest_destructor(void) {
    printf(guest_constructed ? "guest fini\n" : "guest fini without init\n");
}

static void guest_atexit(void* argument) {
    (void)argument;
    printf("guest atexit\n");
}

int main(int argc, char** argv, char** envp) {
    printf("guest main argc=%d\n", argc);
    /* stdout is a pipe here, so glibc buffers it fully from the first line:
     * this stderr line lands ahead of everything the guest printed. */
    fprintf(stderr, "guest stderr\n");
    for (int index = 1; index < argc; ++index) {
        printf("guest argv %s\n", argv[index]);
    }

    const char* value = getenv("SOLO_GUEST_ENV");

    fprintf(stdout, "guest stdout env=%s\n", value ? value : "(unset)");
    printf("guest environ %s\n", environ && *environ && envp ? "present" : "absent");

    /* Repointing environ, the way setproctitle implementations move the
     * environment, must reach getenv and setenv. */
    static char* repointed[] = {"SOLO_GUEST_ENV=repointed", 0};
    char** original = environ;

    environ = repointed;
    value = getenv("SOLO_GUEST_ENV");
    printf("guest environ repointed=%s\n", value ? value : "(unset)");
    environ = original;
    if (__cxa_atexit(guest_atexit, 0, 0)) {
        printf("guest atexit registration failed\n");
    }

    /* musl exports its own __posix_getopt, and optind is one more variable
     * the executable may hold a copy of. */
    char* options[] = {argv[0], "-q", "operand", 0};
    int option = __posix_getopt(3, options, "q");

    printf("guest getopt %c optind=%d\n", option, optind);

    printf("guest tls=%lx bss=%ld\n", guest_tls_data, guest_tls_bss[0]);
    guest_tls_data = 0x600d;

    guest_pthread_t thread;

    if (pthread_create(&thread, 0, guest_thread, 0) || pthread_join(thread, 0)) {
        printf("guest thread failed\n");
    }
    printf("guest tls after thread=%lx\n", guest_tls_data);

    guest_heap_check();
    if (!guest_old_versions_check()) {
        return 1;
    }
    if (!guest_unwind_check()) {
        return 1;
    }

    return 42;
}
