#include "glibc_shim.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define DLFCN_CHECK(condition)                                                  \
    if (!(condition)) {                                                         \
        fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #condition); \
        return 1;                                                               \
    }

namespace {
    using ForeignOperation = int (*)(void*);
    using ForeignInit = int (*)(void*, const void*);
    using ForeignSetType = int (*)(void*, int);
    using ForeignOnce = int (*)(void*, void (*)(void));
    using ForeignWait = int (*)(void*, void*);
    using ForeignBarrierInit = int (*)(void*, const void*, unsigned);
    using ForeignCreate = int (*)(uintptr_t*, const void*, void* (*)(void*), void*);
    using ForeignJoin = int (*)(uintptr_t, void**);
    using ForeignSetStackSize = int (*)(void*, size_t);

    // Every entry point below is the address a loaded glibc DSO would have been
    // relocated to, so the test drives the bridge exactly as a driver does.
    struct Bridge {
        ForeignInit mutexInit;
        ForeignOperation mutexDestroy;
        ForeignOperation mutexLock;
        ForeignOperation mutexTryLock;
        ForeignOperation mutexUnlock;
        ForeignOperation mutexAttributesInit;
        ForeignSetType mutexAttributesSetType;
        ForeignOperation mutexAttributesDestroy;

        ForeignOnce once;

        ForeignInit conditionInit;
        ForeignOperation conditionSignal;
        ForeignOperation conditionDestroy;
        ForeignWait conditionWait;

        ForeignOperation rwlockInit;
        ForeignOperation rwlockReadLock;
        ForeignOperation rwlockUnlock;
        ForeignOperation rwlockDestroy;

        ForeignBarrierInit barrierInit;
        ForeignOperation barrierWait;
        ForeignOperation barrierDestroy;

        ForeignOperation attributesInit;
        ForeignSetStackSize attributesSetStackSize;
        ForeignOperation attributesDestroy;
        ForeignCreate create;
        ForeignJoin join;
    };

    static bool resolved = true;

    template <typename Signature>
    static Signature bridged(const char* name) {
        auto* address = resolveGlibcOverride(name, {});

        if (!address) {
            fprintf(stderr, "bridge symbol missing: %s\n", name);
            resolved = false;
        }

        return reinterpret_cast<Signature>(address);
    }

    static Bridge loadBridge() {
        Bridge bridge;

        bridge.mutexInit = bridged<ForeignInit>("pthread_mutex_init");
        bridge.mutexDestroy = bridged<ForeignOperation>("pthread_mutex_destroy");
        bridge.mutexLock = bridged<ForeignOperation>("pthread_mutex_lock");
        bridge.mutexTryLock = bridged<ForeignOperation>("pthread_mutex_trylock");
        bridge.mutexUnlock = bridged<ForeignOperation>("pthread_mutex_unlock");
        bridge.mutexAttributesInit = bridged<ForeignOperation>("pthread_mutexattr_init");
        bridge.mutexAttributesSetType = bridged<ForeignSetType>("pthread_mutexattr_settype");
        bridge.mutexAttributesDestroy = bridged<ForeignOperation>("pthread_mutexattr_destroy");
        bridge.once = bridged<ForeignOnce>("pthread_once");
        bridge.conditionInit = bridged<ForeignInit>("pthread_cond_init");
        bridge.conditionSignal = bridged<ForeignOperation>("pthread_cond_signal");
        bridge.conditionDestroy = bridged<ForeignOperation>("pthread_cond_destroy");
        bridge.conditionWait = bridged<ForeignWait>("pthread_cond_wait");
        bridge.rwlockInit = bridged<ForeignOperation>("pthread_rwlock_init");
        bridge.rwlockReadLock = bridged<ForeignOperation>("pthread_rwlock_rdlock");
        bridge.rwlockUnlock = bridged<ForeignOperation>("pthread_rwlock_unlock");
        bridge.rwlockDestroy = bridged<ForeignOperation>("pthread_rwlock_destroy");
        bridge.barrierInit = bridged<ForeignBarrierInit>("pthread_barrier_init");
        bridge.barrierWait = bridged<ForeignOperation>("pthread_barrier_wait");
        bridge.barrierDestroy = bridged<ForeignOperation>("pthread_barrier_destroy");
        bridge.attributesInit = bridged<ForeignOperation>("pthread_attr_init");
        bridge.attributesSetStackSize = bridged<ForeignSetStackSize>("pthread_attr_setstacksize");
        bridge.attributesDestroy = bridged<ForeignOperation>("pthread_attr_destroy");
        bridge.create = bridged<ForeignCreate>("pthread_create");
        bridge.join = bridged<ForeignJoin>("pthread_join");

        return bridge;
    }

    static Bridge BRIDGE;

    // glibc encodes the kind of its static recursive and error-check mutex
    // initializers at byte offset 16 and leaves every other byte zero.
    static void staticMutexInitializer(pthread_mutex_t* mutex, int kind) {
        memset(mutex, 0, sizeof(*mutex));
        reinterpret_cast<int*>(mutex)[4] = kind;
    }

    struct TryLockRequest {
        pthread_mutex_t* mutex;
        int result;
    };

    static void* tryLockThread(void* argument) {
        auto* request = static_cast<TryLockRequest*>(argument);

        request->result = BRIDGE.mutexTryLock(request->mutex);
        if (request->result == 0) {
            BRIDGE.mutexUnlock(request->mutex);
        }

        return nullptr;
    }

    static int tryLockFromOtherThread(pthread_mutex_t* mutex) {
        TryLockRequest request{mutex, -1};
        pthread_t thread;

        if (pthread_create(&thread, nullptr, tryLockThread, &request) != 0) {
            return -1;
        }
        pthread_join(thread, nullptr);

        return request.result;
    }

    // The static world holds the object and the bridge locks it: with a shadow
    // registry both sides would take different locks and never exclude.
    static int testSharedObject() {
        pthread_mutex_t mutex;

        staticMutexInitializer(&mutex, 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(pthread_mutex_trylock(&mutex) == EBUSY);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(pthread_mutex_trylock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexTryLock(&mutex) == EBUSY);
        DLFCN_CHECK(pthread_mutex_unlock(&mutex) == 0);

        return 0;
    }

    static int testStaticRecursiveMutex() {
        pthread_mutex_t mutex;

        staticMutexInitializer(&mutex, 1);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(tryLockFromOtherThread(&mutex) == EBUSY);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(tryLockFromOtherThread(&mutex) == EBUSY);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(tryLockFromOtherThread(&mutex) == 0);

        return 0;
    }

    static int testStaticErrorCheckMutex() {
        pthread_mutex_t mutex;

        staticMutexInitializer(&mutex, 2);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == EDEADLK);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);

        return 0;
    }

    static int testAttributedMutex() {
        pthread_mutex_t mutex;
        int attributes = 0;

        DLFCN_CHECK(BRIDGE.mutexAttributesInit(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexAttributesSetType(&attributes, 1) == 0);
        DLFCN_CHECK(BRIDGE.mutexInit(&mutex, &attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexAttributesDestroy(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexDestroy(&mutex) == 0);

        return 0;
    }

    // A destroyed object whose storage is reused must not inherit the type or
    // the lock state of its predecessor.
    static int testReusedStorage() {
        pthread_mutex_t mutex;
        int attributes = 0;

        DLFCN_CHECK(BRIDGE.mutexAttributesInit(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexAttributesSetType(&attributes, 1) == 0);
        DLFCN_CHECK(BRIDGE.mutexInit(&mutex, &attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexAttributesDestroy(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexDestroy(&mutex) == 0);

        DLFCN_CHECK(BRIDGE.mutexInit(&mutex, nullptr) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexTryLock(&mutex) == EBUSY);
        DLFCN_CHECK(BRIDGE.mutexUnlock(&mutex) == 0);
        DLFCN_CHECK(BRIDGE.mutexDestroy(&mutex) == 0);

        return 0;
    }

    static pthread_once_t ONCE_FLAG;
    static int ONCE_COUNT;

    static void countOnce() {
        ++ONCE_COUNT;
    }

    static void* onceThread(void*) {
        BRIDGE.once(&ONCE_FLAG, countOnce);

        return nullptr;
    }

    static int testOnce() {
        static constexpr size_t threadCount = 8;
        pthread_t threads[threadCount];

        memset(&ONCE_FLAG, 0, sizeof(ONCE_FLAG));
        ONCE_COUNT = 0;
        for (auto& thread : threads) {
            DLFCN_CHECK(pthread_create(&thread, nullptr, onceThread, nullptr) == 0);
        }
        for (auto thread : threads) {
            DLFCN_CHECK(pthread_join(thread, nullptr) == 0);
        }
        DLFCN_CHECK(ONCE_COUNT == 1);

        return 0;
    }

    static pthread_barrier_t BARRIER;
    static int BARRIER_SERIAL;

    static void* barrierThread(void*) {
        if (BRIDGE.barrierWait(&BARRIER) == PTHREAD_BARRIER_SERIAL_THREAD) {
            __atomic_fetch_add(&BARRIER_SERIAL, 1, __ATOMIC_RELAXED);
        }

        return nullptr;
    }

    static int testBarrier() {
        static constexpr size_t threadCount = 4;
        pthread_t threads[threadCount];

        BARRIER_SERIAL = 0;
        DLFCN_CHECK(BRIDGE.barrierInit(&BARRIER, nullptr, threadCount) == 0);
        for (auto& thread : threads) {
            DLFCN_CHECK(pthread_create(&thread, nullptr, barrierThread, nullptr) == 0);
        }
        for (auto thread : threads) {
            DLFCN_CHECK(pthread_join(thread, nullptr) == 0);
        }
        DLFCN_CHECK(BARRIER_SERIAL == 1);
        DLFCN_CHECK(BRIDGE.barrierDestroy(&BARRIER) == 0);

        return 0;
    }

    static int testRwlock() {
        pthread_rwlock_t rwlock;

        memset(&rwlock, 0, sizeof(rwlock));
        DLFCN_CHECK(BRIDGE.rwlockInit(&rwlock) == 0);
        DLFCN_CHECK(BRIDGE.rwlockReadLock(&rwlock) == 0);
        DLFCN_CHECK(BRIDGE.rwlockReadLock(&rwlock) == 0);
        DLFCN_CHECK(pthread_rwlock_trywrlock(&rwlock) == EBUSY);
        DLFCN_CHECK(BRIDGE.rwlockUnlock(&rwlock) == 0);
        DLFCN_CHECK(BRIDGE.rwlockUnlock(&rwlock) == 0);
        DLFCN_CHECK(pthread_rwlock_trywrlock(&rwlock) == 0);
        DLFCN_CHECK(pthread_rwlock_unlock(&rwlock) == 0);
        DLFCN_CHECK(BRIDGE.rwlockDestroy(&rwlock) == 0);

        return 0;
    }

    static pthread_mutex_t CONDITION_MUTEX;
    static pthread_cond_t CONDITION;
    static int CONDITION_READY;

    static void* conditionThread(void*) {
        BRIDGE.mutexLock(&CONDITION_MUTEX);
        CONDITION_READY = 1;
        BRIDGE.conditionSignal(&CONDITION);
        BRIDGE.mutexUnlock(&CONDITION_MUTEX);

        return nullptr;
    }

    static int testCondition() {
        pthread_t thread;

        staticMutexInitializer(&CONDITION_MUTEX, 0);
        memset(&CONDITION, 0, sizeof(CONDITION));
        CONDITION_READY = 0;
        DLFCN_CHECK(BRIDGE.conditionInit(&CONDITION, nullptr) == 0);
        DLFCN_CHECK(BRIDGE.mutexLock(&CONDITION_MUTEX) == 0);
        DLFCN_CHECK(pthread_create(&thread, nullptr, conditionThread, nullptr) == 0);
        while (!CONDITION_READY) {
            DLFCN_CHECK(BRIDGE.conditionWait(&CONDITION, &CONDITION_MUTEX) == 0);
        }
        DLFCN_CHECK(BRIDGE.mutexUnlock(&CONDITION_MUTEX) == 0);
        DLFCN_CHECK(pthread_join(thread, nullptr) == 0);
        DLFCN_CHECK(BRIDGE.conditionDestroy(&CONDITION) == 0);

        return 0;
    }

    static int STARTED;

    static void* startedThread(void*) {
        __atomic_store_n(&STARTED, 1, __ATOMIC_RELEASE);

        return reinterpret_cast<void*>(42);
    }

    static int testThreadAttributes() {
        pthread_attr_t attributes;
        uintptr_t thread = 0;
        void* result = nullptr;

        STARTED = 0;
        DLFCN_CHECK(BRIDGE.attributesInit(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.attributesSetStackSize(&attributes, 256 * 1024) == 0);
        DLFCN_CHECK(BRIDGE.create(&thread, &attributes, startedThread, nullptr) == 0);
        DLFCN_CHECK(BRIDGE.attributesDestroy(&attributes) == 0);
        DLFCN_CHECK(BRIDGE.join(thread, &result) == 0);
        DLFCN_CHECK(__atomic_load_n(&STARTED, __ATOMIC_ACQUIRE) == 1);
        DLFCN_CHECK(reinterpret_cast<uintptr_t>(result) == 42);

        return 0;
    }

    struct Test {
        const char* name;
        int (*run)();
    };

    static const Test TESTS[] = {
        {"shared object between both worlds", testSharedObject},
        {"glibc static recursive initializer", testStaticRecursiveMutex},
        {"glibc static error-check initializer", testStaticErrorCheckMutex},
        {"mutex created through bridged attributes", testAttributedMutex},
        {"reused mutex storage", testReusedStorage},
        {"pthread_once from many threads", testOnce},
        {"barrier across threads", testBarrier},
        {"rwlock shared with both worlds", testRwlock},
        {"condition variable handoff", testCondition},
        {"thread attributes and create/join", testThreadAttributes},
    };
}

int main() {
    BRIDGE = loadBridge();
    if (!resolved) {
        return 1;
    }

    for (const auto& test : TESTS) {
        if (test.run()) {
            fprintf(stderr, "pthread bridge: %s: FAILED\n", test.name);
            return 1;
        }
        printf("pthread bridge: %s: ok\n", test.name);
    }

    return 0;
}
