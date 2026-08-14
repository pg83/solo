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
    int stub_dlclose(void* handle);
    char* stub_dlerror(void);
    void stub_dlregister(const char* lib, const char* symbol, void* ptr);
    int stub_dladdr(const void* addr, Dl_info* info);

#if defined(__cplusplus)
}
#endif
