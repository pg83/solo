#pragma once

// interface
#undef RTLD_LAZY
#undef RTLD_NOW
#undef RTLD_GLOBAL
#undef RTLD_LOCAL
#undef RTLD_NODELETE
#undef RTLD_NOLOAD
#undef RTLD_DEEPBIND
#undef RTLD_NEXT
#undef RTLD_DEFAULT

#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_GLOBAL 4
#define RTLD_LOCAL 8
#define RTLD_NODELETE 16
#define RTLD_NOLOAD 32
#define RTLD_DEEPBIND 64

#define RTLD_NEXT RTLD_DEFAULT
#define RTLD_DEFAULT stub_dlopen(0, 0)

#if !defined(COMPILE_DLOPEN)
    #define dlsym stub_dlsym
    #define dlopen stub_dlopen
    #define dlclose stub_dlclose
    #define dlerror stub_dlerror
    #define dladdr stub_dladdr
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(_DLFCN_H)
    typedef struct {
        const char* dli_fname;
        void* dli_fbase;
        const char* dli_sname;
        void* dli_saddr;
    } Dl_info;
#endif

    void* stub_dlsym(void* handle, const char* symbol);
    void* stub_dlopen(const char* filename, int flags);
    // The dlopen issued by loaded code: caller indexes the loader's dlopen
    // caller pool and names the issuing image, whose DT_RPATH/DT_RUNPATH
    // join the library search for names without a slash. ~0u means no
    // caller and behaves like stub_dlopen.
    void* stub_dlopen_caller(unsigned caller, const char* filename, int flags);
    int stub_dlclose(void* handle);
    char* stub_dlerror(void);
    // Startup wiring: the registry is unsynchronized, so finish every
    // registration before creating threads and before the first dlopen.
    void stub_dlregister(const char* lib, const char* symbol, void* ptr);
    int stub_dladdr(const void* addr, Dl_info* info);

    // A bundle is a stub and its guest in one file: the stub is an ordinary
    // static executable that links this loader, and the guest program —
    // together with whichever shared objects should come from the bundle
    // rather than from the machine — is appended to it. The stub finds the
    // payload through its own /proc/self/exe, so nothing is unpacked and no
    // path outside the file is consulted for a bundled name.
    //
    // This is the `solo run` model, not the PT_INTERP one: the stub stays
    // the process's main executable, so musl sizes the static TLS from the
    // stub's own program headers and the loader's TLS pad exists. An
    // interpreter has no pad to hand out, which is why a bundle is built
    // this way.
    //
    // A stub is expected to be small:
    //
    //     #include <dlfcn.h>
    //
    //     int main(int argc, char** argv) {
    //         return soloBundleMain(argc, argv);
    //     }
    //
    // Link it against this loader and against the static libraries whose
    // symbols should satisfy the guest's DT_NEEDED: the provider registry
    // stub_dlregister() builds is consulted before any bundled or host file,
    // so a library linked into the stub answers for its soname outright.

    // Non-zero when this executable has a payload appended to it. A stub
    // built for one program can skip the test; solo's own command uses it
    // to tell a bundle from a plain invocation.
    int soloHasBundle(void);

    // Runs the bundled guest, with argv passed through exactly as received
    // — argv[0] included. The stub's file is the program as far as the
    // guest can tell, so its /proc/self/exe, its argv[0], and any re-exec of
    // itself all name the bundle and keep working.
    //
    // Does not return when the guest starts. On failure the reason is on
    // stderr and the result is 127, the exit status ld.so uses when it
    // cannot start a program.
    int soloBundleMain(int argc, char** argv);

#if defined(__cplusplus)
}
#endif
