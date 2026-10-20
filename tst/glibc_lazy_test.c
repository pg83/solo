/* Lazy-binding conformance: built against the real glibc, loaded through
 * SoLo. The undefined function makes eager binding fail while lazy binding
 * must succeed as long as nothing calls it; the other entry points call
 * through the PLT, so the first call runs the lazy resolver with integer and
 * floating-point arguments live in registers. */

extern int getpid(void);
extern int getppid(void);
extern void* dlopen(const char* path, int flags);
extern char* dlerror(void);

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
    return dlerror() ? 0 : 3;
}
