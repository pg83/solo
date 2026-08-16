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

enum {
    GlibcObjectCount = 600,
    GlibcAttributeCount = 80,
};

union GlibcPthreadObject {
    unsigned char bytes[64];
    unsigned long alignment;
};

static union GlibcPthreadObject mutexes[GlibcObjectCount];
static union GlibcPthreadObject onceFlags[GlibcObjectCount];
static union GlibcPthreadObject conditions[GlibcObjectCount];
static union GlibcPthreadObject rwlocks[GlibcObjectCount];
static union GlibcPthreadObject barriers[GlibcObjectCount];
static union GlibcPthreadObject threadAttributes[GlibcAttributeCount];
static int onceCalls;

static void countOnceCall(void) {
    ++onceCalls;
}

int glibc_test_many_pthread_objects(void) {
    typedef int (*Init)(void*, const void*);
    typedef int (*Destroy)(void*);
    typedef int (*Lock)(void*);
    typedef int (*Once)(void*, void (*)(void));
    typedef int (*BarrierInit)(void*, const void*, unsigned);
    typedef int (*AttributeInit)(void*);
    typedef int (*AttributeSetstacksize)(void*, unsigned long);

    void* handle = openLibrary("libpthread.so.0");
    Init mutexInit = handle ? (Init)dlsym(handle, "pthread_mutex_init") : (Init)0;
    Destroy mutexDestroy = handle ? (Destroy)dlsym(handle, "pthread_mutex_destroy") : (Destroy)0;
    Lock mutexLock = handle ? (Lock)dlsym(handle, "pthread_mutex_lock") : (Lock)0;
    Lock mutexUnlock = handle ? (Lock)dlsym(handle, "pthread_mutex_unlock") : (Lock)0;
    Once once = handle ? (Once)dlsym(handle, "pthread_once") : (Once)0;
    Init conditionInit = handle ? (Init)dlsym(handle, "pthread_cond_init") : (Init)0;
    Destroy conditionDestroy = handle ? (Destroy)dlsym(handle, "pthread_cond_destroy") : (Destroy)0;
    Lock conditionSignal = handle ? (Lock)dlsym(handle, "pthread_cond_signal") : (Lock)0;
    Init rwlockInit = handle ? (Init)dlsym(handle, "pthread_rwlock_init") : (Init)0;
    Destroy rwlockDestroy = handle ? (Destroy)dlsym(handle, "pthread_rwlock_destroy") : (Destroy)0;
    Lock rwlockReadLock = handle ? (Lock)dlsym(handle, "pthread_rwlock_rdlock") : (Lock)0;
    Lock rwlockUnlock = handle ? (Lock)dlsym(handle, "pthread_rwlock_unlock") : (Lock)0;
    BarrierInit barrierInit = handle ? (BarrierInit)dlsym(handle, "pthread_barrier_init") : (BarrierInit)0;
    Destroy barrierDestroy = handle ? (Destroy)dlsym(handle, "pthread_barrier_destroy") : (Destroy)0;
    Lock barrierWait = handle ? (Lock)dlsym(handle, "pthread_barrier_wait") : (Lock)0;
    AttributeInit attributeInit = handle ? (AttributeInit)dlsym(handle, "pthread_attr_init") : (AttributeInit)0;
    Destroy attributeDestroy = handle ? (Destroy)dlsym(handle, "pthread_attr_destroy") : (Destroy)0;
    AttributeSetstacksize attributeSetstacksize = handle ? (AttributeSetstacksize)dlsym(handle, "pthread_attr_setstacksize") : (AttributeSetstacksize)0;

    if (!mutexInit || !mutexDestroy || !mutexLock || !mutexUnlock || !once || !conditionInit || !conditionDestroy || !conditionSignal || !rwlockInit || !rwlockDestroy || !rwlockReadLock || !rwlockUnlock || !barrierInit || !barrierDestroy || !barrierWait || !attributeInit || !attributeDestroy || !attributeSetstacksize) {
        return 1;
    }

    for (int index = 0; index < GlibcObjectCount; ++index) {
        if (mutexInit(&mutexes[index], (void*)0) != 0) {
            return 2;
        }
        if (conditionInit(&conditions[index], (void*)0) != 0) {
            return 3;
        }
        if (rwlockInit(&rwlocks[index], (void*)0) != 0) {
            return 4;
        }
        if (barrierInit(&barriers[index], (void*)0, 1) != 0) {
            return 5;
        }
        if (once(&onceFlags[index], countOnceCall) != 0) {
            return 6;
        }
    }
    if (onceCalls != GlibcObjectCount) {
        return 7;
    }

    for (int index = 0; index < GlibcAttributeCount; ++index) {
        if (attributeInit(&threadAttributes[index]) != 0) {
            return 8;
        }
        if (attributeSetstacksize(&threadAttributes[index], 65536) != 0) {
            return 9;
        }
    }

    for (int index = 0; index < GlibcObjectCount; ++index) {
        if (mutexLock(&mutexes[index]) != 0 || mutexUnlock(&mutexes[index]) != 0) {
            return 10;
        }
        if (conditionSignal(&conditions[index]) != 0) {
            return 11;
        }
        if (rwlockReadLock(&rwlocks[index]) != 0 || rwlockUnlock(&rwlocks[index]) != 0) {
            return 12;
        }
        int barrierResult = barrierWait(&barriers[index]);
        if (barrierResult != 0 && barrierResult != -1) {
            return 13;
        }
    }

    for (int index = 0; index < GlibcAttributeCount; ++index) {
        if (attributeDestroy(&threadAttributes[index]) != 0) {
            return 14;
        }
    }
    for (int index = 0; index < GlibcObjectCount; ++index) {
        if (barrierDestroy(&barriers[index]) != 0 || rwlockDestroy(&rwlocks[index]) != 0 || conditionDestroy(&conditions[index]) != 0 || mutexDestroy(&mutexes[index]) != 0) {
            return 15;
        }
    }

    return 0;
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
