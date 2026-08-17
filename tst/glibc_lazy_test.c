/* Lazy-binding conformance: built against the real glibc, loaded through
 * SoLo. The undefined function makes eager binding fail while lazy binding
 * must succeed as long as nothing calls it; the other entry points call
 * through the PLT, so the first call runs the lazy resolver with integer and
 * floating-point arguments live in registers. */

extern int getpid(void);

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
