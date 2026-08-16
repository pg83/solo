typedef unsigned long GlibcThread;

extern void* dlopen(const char* path, int flags);
extern void* dlsym(void* handle, const char* name);
extern int dlclose(void* handle);
extern char* dlerror(void);
extern void* dlvsym(void* handle, const char* name, const char* version);

enum {
    GlibcRtldLazy = 1,
};

static void* openLibrary(const char* library) {
    return dlopen(library, GlibcRtldLazy);
}

void* glibc_test_lookup(const char* library, const char* symbol) {
    void* handle = openLibrary(library);

    return handle ? dlsym(handle, symbol) : (void*)0;
}

void* glibc_test_default_lookup(const char* symbol) {
    return dlsym((void*)0, symbol);
}

void* glibc_test_version_lookup(const char* library, const char* symbol, const char* version) {
    void* handle = openLibrary(library);

    return handle ? dlvsym(handle, symbol, version) : (void*)0;
}

int glibc_test_marker(void) {
    return 97;
}

int glibc_test_factory(void) {
    typedef int (*FactoryFunction)(int);

    void* handle = openLibrary("libtest-provider.so.7");
    FactoryFunction function = handle ? (FactoryFunction)dlsym(handle, "test_provider_value") : (FactoryFunction)0;

    int result = function ? function(7) : -1;

    if (handle && dlclose(handle) != 0) {
        return -2;
    }

    return result;
}

int glibc_test_own_symbol(void) {
    typedef int (*MarkerFunction)(void);

    void* handle = openLibrary("libdlfcn-test-glibc.so");
    MarkerFunction marker = handle ? (MarkerFunction)dlsym(handle, "glibc_test_marker") : (MarkerFunction)0;

    int result = marker ? marker() : -1;

    if (handle && dlclose(handle) != 0) {
        return -2;
    }

    return result;
}

static void* glibcThreadStart(void* argument) {
    int* value = (int*)argument;

    *value = 73;

    return argument;
}

int glibc_test_thread(void) {
    typedef int (*AttrInit)(void*);
    typedef int (*AttrDestroy)(void*);
    typedef int (*AttrSetstacksize)(void*, unsigned long);
    typedef int (*ThreadCreate)(GlibcThread*, const void*, void* (*)(void*), void*);
    typedef int (*ThreadJoin)(GlibcThread, void**);

    union {
        unsigned char bytes[64];
        unsigned long alignment;
    } attributes;
    void* handle = openLibrary("libpthread.so.0");
    AttrInit attrInit = handle ? (AttrInit)dlsym(handle, "pthread_attr_init") : (AttrInit)0;
    AttrDestroy attrDestroy = handle ? (AttrDestroy)dlsym(handle, "pthread_attr_destroy") : (AttrDestroy)0;
    AttrSetstacksize attrSetstacksize = handle ? (AttrSetstacksize)dlsym(handle, "pthread_attr_setstacksize") : (AttrSetstacksize)0;
    ThreadCreate threadCreate = handle ? (ThreadCreate)dlsym(handle, "pthread_create") : (ThreadCreate)0;
    ThreadJoin threadJoin = handle ? (ThreadJoin)dlsym(handle, "pthread_join") : (ThreadJoin)0;
    GlibcThread thread = 0;
    void* result = (void*)0;
    int value = 0;

    if (!attrInit || !attrDestroy || !attrSetstacksize || !threadCreate || !threadJoin) {
        return 1;
    }
    if (attrInit(&attributes) != 0) {
        return 2;
    }
    if (attrSetstacksize(&attributes, 65536) != 0) {
        return 3;
    }
    if (threadCreate(&thread, &attributes, glibcThreadStart, &value) != 0) {
        return 4;
    }
    if (threadJoin(thread, &result) != 0) {
        return 5;
    }
    if (attrDestroy(&attributes) != 0) {
        return 6;
    }

    return value == 73 && result == &value ? 0 : 7;
}

int glibc_test_error(void) {
    void* handle = openLibrary("libc.so.6");

    if (!handle) {
        return 1;
    }
    dlerror();
    if (dlsym(handle, "dlfcn_symbol_that_does_not_exist")) {
        return 2;
    }
    if (!dlerror()) {
        return 3;
    }
    if (dlerror()) {
        return 4;
    }
    if (dlvsym(handle, "pthread_create", "GLIBC_999.0")) {
        return 5;
    }
    if (!dlerror()) {
        return 6;
    }

    return 0;
}

int glibc_test_close(void) {
    void* handle = openLibrary("libc.so.6");

    return handle ? dlclose(handle) : -1;
}

void* glibc_test_dl_function(const char* symbol) {
    return glibc_test_lookup("libdl.so.2", symbol);
}
