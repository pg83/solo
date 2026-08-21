/* Caller-RUNPATH conformance: built with -Wl,-rpath,'$ORIGIN/runpath', the
 * host loads its sibling by a bare name that no other search path carries,
 * so the load succeeds only when the caller's DT_RUNPATH joins the search. */

extern void* dlopen(const char* filename, int flags);
extern void* dlsym(void* handle, const char* symbol);

#define RTLD_NOW 2
#define RTLD_LOCAL 0

typedef int (*GlibcRunpathValue)(void);

int glibc_runpath_host_value(void) {
    void* handle = dlopen("libdlfcn-test-runpath-sibling.so", RTLD_NOW | RTLD_LOCAL);

    if (!handle) {
        return 0;
    }

    GlibcRunpathValue value = (GlibcRunpathValue)dlsym(handle, "glibc_runpath_sibling_value");

    return value ? value() : 0;
}

/* Compiled at -O2 this forwarder becomes a tail jump, so a return address
 * would name the static caller, which has no RUNPATH; the attribution must
 * come from the relocation-time caller binding instead. */
void* glibc_runpath_tail_open(const char* name, int flags) {
    return dlopen(name, flags);
}
