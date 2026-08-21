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

    return 42;
}
