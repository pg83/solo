/* Lazy-binding conformance: built against the real glibc, loaded through
 * SoLo. The undefined function makes eager binding fail while lazy binding
 * must succeed as long as nothing calls it; the other entry points call
 * through the PLT, so the first call runs the lazy resolver with integer and
 * floating-point arguments live in registers. */

extern int getpid(void);
extern int getppid(void);
extern void* dlopen(const char* path, int flags);
extern void* dlsym(void* handle, const char* name);
extern char* dlerror(void);
extern char* strstr(const char* text, const char* part);
extern const char* gnu_get_libc_version(void);
extern const char* gnu_get_libc_release(void);

extern int dlfcn_lazy_undefined_function(void);

int glibc_lazy_helper(int value) {
    return value + 29;
}

int glibc_lazy_missing_caller(void) {
    return dlfcn_lazy_undefined_function();
}

int glibc_lazy_value(int value) {
    return glibc_lazy_helper(value) + 1;
}

double glibc_lazy_mix(int a, double b, long c, double d) {
    return glibc_lazy_helper(a) + b * c + d;
}

int glibc_lazy_pid(void) {
    return getpid();
}

/* A failed dlopen's message must survive the lazy binding of the calls that
 * follow it, getppid's and dlerror's own, as it does under ld.so. */
int glibc_lazy_dlerror_kept(void) {
    if (dlopen("/nonexistent/libdlfcn-test-missing.so", 2)) {
        return 1;
    }
    if (getppid() < 0) {
        return 2;
    }
    const char* error = dlerror();
    if (!error || !strstr(error, "libdlfcn-test-missing.so")) {
        return 3;
    }
    return dlerror() ? 4 : 0;
}

/* These glibc-only functions require a failed musl probe before the shim
 * fallback. Its internal error must neither overwrite an already returned
 * message nor leave a new pending error. Each call uses a fresh PLT slot. */
int glibc_lazy_dlerror_returned(void) {
    for (int shortError = 0; shortError != 2; ++shortError) {
        if (shortError) {
            if (dlsym((void*)0, (const char*)0)) {
                return 1;
            }
        } else if (dlopen("/nonexistent/libdlfcn-test-returned-error.so", 2)) {
            return 2;
        }

        const char* error = dlerror();
        if (!error || !error[0]) {
            return 3;
        }

        /* Copy and compare without calls that could bind another PLT slot
         * between taking the error and testing its lifetime. */
        char saved[1024];
        unsigned length = 0;
        do {
            saved[length] = error[length];
        } while (error[length++] && length < sizeof(saved));
        if (length == sizeof(saved)) {
            return 4;
        }

        const char* value = shortError ? gnu_get_libc_release() : gnu_get_libc_version();
        if (!value || !value[0]) {
            return 5;
        }
        for (unsigned index = 0; index < length; ++index) {
            if (error[index] != saved[index]) {
                return 6 + shortError;
            }
        }
        if (dlerror()) {
            return 8;
        }
    }
    return 0;
}
