/* A whole glibc executable for `solo run`: linked against the sysroot's
 * Scrt1.o and libc.so.6, so its _start is glibc's own crt and its startup
 * goes through the bridge's __libc_start_main. Self-declared prototypes keep
 * it independent of the compiling host's headers, like glibc_test.c. The
 * stdout and environ references compile to copy relocations on toolchains
 * that favor direct access in PIE code, and to GOT loads elsewhere — both
 * paths must work. */

typedef struct guest_file FILE;

extern FILE* stdout;
extern char** environ;

int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
char* getenv(const char* name);
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

static void guest_old_versions_check(void) {
    guest_glob_t found = {0};
    int matches = guest_glob64_old("/", 0, 0, &found) == 0 ? (int)found.gl_pathc : -1;

    if (matches >= 0) {
        globfree64(&found);
    }

    /* A default mutex is all zeroes, the size of the largest pthread_mutex_t. */
    _Alignas(16) unsigned char mutex[64] = {0};
    struct guest_timespec deadline;

    clock_gettime(1, &deadline);
    deadline.tv_sec += 1;

    int locked = guest_clocklock_old(mutex, 1, &deadline);

    if (!locked) {
        pthread_mutex_unlock(mutex);
    }
    printf("guest old versions glob64=%d clocklock=%d\n", matches, locked);
}

typedef unsigned long guest_pthread_t;
int pthread_create(guest_pthread_t* thread, const void* attributes, void* (*function)(void*), void* argument);
int pthread_join(guest_pthread_t thread, void** result);

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

__attribute__((constructor)) static void guest_constructor(void) {
    printf("guest init\n");
}

static void guest_atexit(void* argument) {
    (void)argument;
    printf("guest atexit\n");
}

int main(int argc, char** argv, char** envp) {
    printf("guest main argc=%d\n", argc);
    for (int index = 1; index < argc; ++index) {
        printf("guest argv %s\n", argv[index]);
    }

    const char* value = getenv("SOLO_GUEST_ENV");

    fprintf(stdout, "guest stdout env=%s\n", value ? value : "(unset)");
    printf("guest environ %s\n", environ && *environ && envp ? "present" : "absent");
    if (__cxa_atexit(guest_atexit, 0, 0)) {
        printf("guest atexit registration failed\n");
    }

    printf("guest tls=%lx bss=%ld\n", guest_tls_data, guest_tls_bss[0]);
    guest_tls_data = 0x600d;

    guest_pthread_t thread;

    if (pthread_create(&thread, 0, guest_thread, 0) || pthread_join(thread, 0)) {
        printf("guest thread failed\n");
    }
    printf("guest tls after thread=%lx\n", guest_tls_data);

    guest_old_versions_check();

    return 42;
}
