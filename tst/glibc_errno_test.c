#ifdef ERRNO_LIBRARY
#ifdef OWN_ERRNO
_Thread_local int errno = 37;
#endif

int errnoLibraryValue(void) {
    return 7;
}
#else
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void* scopes[5];
static void* empty;
static void* owned;
static pthread_barrier_t barrier;

static void require(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "errno lookup: %s\n", message);
        _Exit(1);
    }
}

static void checkLookup(void* handle, const char* version, int* expected) {
    dlerror();
    int* address = version ? dlvsym(handle, "errno", version) : dlsym(handle, "errno");
    const char* error = dlerror();

    require(address == expected, version ? "wrong versioned address" : "wrong unversioned address");
    require((error != NULL) == (expected == NULL), "wrong dlerror state");
    require(dlerror() == NULL, "dlerror was not consumed");
}

static void checkScopes(void) {
    for (unsigned index = 0; index < sizeof(scopes) / sizeof(scopes[0]); ++index) {
        checkLookup(scopes[index], NULL, &errno);
        checkLookup(scopes[index], "GLIBC_PRIVATE", &errno);
        checkLookup(scopes[index], "GLIBC_NOT_A_VERSION", NULL);
    }
    checkLookup(empty, NULL, NULL);
    checkLookup(empty, "GLIBC_PRIVATE", NULL);
}

struct Worker {
    pthread_t thread;
    int index;
    int* real;
    int* own;
};

static void* workerMain(void* opaque) {
    struct Worker* worker = opaque;

    checkScopes();
    worker->real = &errno;
    worker->own = dlsym(owned, "errno");
    require(worker->own != NULL && worker->own != worker->real && *worker->own == 37, "own TLS definition missing");
    checkLookup(owned, "GLIBC_PRIVATE", worker->own);
    checkLookup(owned, "GLIBC_NOT_A_VERSION", NULL);
    *worker->own = 100 + worker->index;
    errno = 200 + worker->index;
    pthread_barrier_wait(&barrier);
    require(errno == 200 + worker->index && *worker->own == 100 + worker->index, "another thread changed errno");
    pthread_barrier_wait(&barrier);
    return NULL;
}

int main(int argc, char** argv) {
    require(argc == 5, "expected four library paths");
    scopes[0] = RTLD_DEFAULT;
    scopes[1] = dlopen(NULL, RTLD_NOW);
    scopes[2] = dlopen("libc.so.6", RTLD_NOW);
    scopes[3] = dlopen(argv[2], RTLD_NOW);
    scopes[4] = dlopen(argv[3], RTLD_NOW);
    empty = dlopen(argv[1], RTLD_NOW);
    require(scopes[1] && scopes[2] && scopes[3] && scopes[4] && empty, "scope library failed to load");
    checkScopes();
    checkLookup(RTLD_NEXT, NULL, &errno);
    checkLookup(RTLD_NEXT, "GLIBC_PRIVATE", &errno);
    owned = dlopen(argv[4], RTLD_NOW);
    require(owned != NULL, "TLS library failed to load");
    int* own = dlsym(owned, "errno");

    require(own != NULL && own != &errno && *own == 37, "own definition was replaced by libc");
    checkLookup(owned, "GLIBC_PRIVATE", own);
    checkLookup(owned, "GLIBC_NOT_A_VERSION", NULL);
    struct Worker workers[4] = {0};

    require(!pthread_barrier_init(&barrier, NULL, 5), "barrier initialization failed");
    for (int index = 0; index < 4; ++index) {
        workers[index].index = index;
        require(!pthread_create(&workers[index].thread, NULL, workerMain, &workers[index]), "thread creation failed");
    }
    *own = 444;
    errno = 333;
    pthread_barrier_wait(&barrier);
    require(errno == 333 && *own == 444, "worker changed the main thread storage");
    for (int index = 0; index < 4; ++index) {
        require(workers[index].real != &errno && workers[index].own != own, "TLS storage shared with main");
        for (int other = 0; other < index; ++other) {
            require(workers[index].real != workers[other].real && workers[index].own != workers[other].own, "TLS storage shared between workers");
        }
    }
    pthread_barrier_wait(&barrier);
    for (int index = 0; index < 4; ++index) {
        require(!pthread_join(workers[index].thread, NULL), "thread join failed");
    }
    require(!pthread_barrier_destroy(&barrier), "barrier destruction failed");
    puts("errno lookup: scopes, versions, own definition, per-thread storage: ok");
    return 0;
}
#endif
