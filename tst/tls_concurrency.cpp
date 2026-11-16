#include "dlfcn.h"

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

// Linker wrappers belong only to this test executable. Pause creation after
// TLS was copied but before the child joins musl's ring, then load a module.
// No sleeps or scheduler luck decide whether the two operations overlap.
extern "C" void* __real___copy_tls(unsigned char* memory);
extern "C" int __real_pthread_rwlock_wrlock(pthread_rwlock_t* lock);
extern "C" void __real___tl_lock();
extern "C" void __real___tl_unlock();

namespace {
    using Check = int (*)(int);
    using Address = int* (*)();

    struct State;

    struct Worker {
        State* state;
        int value;
        pthread_t thread;
        int* address;
    };

    struct State {
        const char* path;
        sem_t create;
        sem_t copied;
        sem_t resumeCopy;
        sem_t load;
        sem_t registration;
        sem_t created;
        sem_t ready;
        pthread_barrier_t writes;
        pthread_t loader;
        Worker workers[4];
        Check check;
        Check verify;
        Address address;
        int* loaderAddress;
        int pauseCopy;
        bool creationBlocked;
        volatile sig_atomic_t traversing;
        volatile sig_atomic_t signals;
        volatile sig_atomic_t signalInTraversal;
        unsigned traversals;
    };

    static State* active;

    static void require(bool condition, const char* message) {
        if (!condition) {
            fprintf(stderr, "TLS concurrency: %s (errno=%d)\n", message, errno);
            // A failed invariant can leave another thread deliberately
            // parked inside libc. Exit without running loader finalizers.
            _Exit(1);
        }
    }

    static void wait(sem_t& semaphore) {
        int result;
        do {
            result = sem_wait(&semaphore);
        } while (result && errno == EINTR);
        require(!result, "semaphore wait failed");
    }

    static void post(sem_t& semaphore) {
        require(!sem_post(&semaphore), "semaphore post failed");
    }

    static State* loadingState() {
        auto* state = __atomic_load_n(&active, __ATOMIC_ACQUIRE);

        return state && pthread_equal(pthread_self(), state->loader) ? state : nullptr;
    }

    static void onSignal(int) {
        auto* state = __atomic_load_n(&active, __ATOMIC_RELAXED);

        if (state) {
            state->signals = state->signals + 1;
            if (state->traversing) {
                state->signalInTraversal = 1;
            }
        }
    }

    static void* workerMain(void* opaque) {
        auto& worker = *static_cast<Worker*>(opaque);
        auto& state = *worker.state;

        wait(state.ready);
        require(!state.check(worker.value), "thread lost its TLS template");
        worker.address = state.address();
        pthread_barrier_wait(&state.writes);
        require(!state.verify(worker.value), "another thread changed this thread's TLS");
        return nullptr;
    }

    static void* creatorMain(void* opaque) {
        auto& state = *static_cast<State*>(opaque);

        wait(state.create);
        require(!pthread_create(&state.workers[3].thread, nullptr, workerMain, &state.workers[3]), "child creation failed");
        post(state.created);
        return workerMain(&state.workers[2]);
    }

    static void* futureMain(void* opaque) {
        auto& worker = *static_cast<Worker*>(opaque);
        auto& state = *worker.state;

        require(!state.check(worker.value) && !state.verify(worker.value), "future thread lost its TLS template");
        worker.address = state.address();
        return nullptr;
    }

    static void* loaderMain(void* opaque) {
        auto& state = *static_cast<State*>(opaque);
        sigset_t original;
        sigset_t mask;

        wait(state.load);
        require(!pthread_sigmask(SIG_SETMASK, nullptr, &original), "cannot read signal mask");
        mask = original;
        sigdelset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        require(!pthread_sigmask(SIG_SETMASK, &mask, nullptr), "cannot set signal mask");

        auto* module = stub_dlopen(state.path, RTLD_NOW | RTLD_LOCAL);

        if (!module) {
            fprintf(stderr, "TLS concurrency load: %s\n", stub_dlerror());
        }
        require(module, "dlopen failed");
        require(state.creationBlocked, "registration did not wait for in-flight pthread_create");
        require(state.traversals == 1, "expected one TLS registration");
        require(state.signals == 1 && !state.signalInTraversal, "signal was not deferred until thread-list unlock");
        require(!pthread_sigmask(SIG_SETMASK, nullptr, &mask), "cannot read restored mask");
        require(!sigismember(&mask, SIGUSR1) && sigismember(&mask, SIGUSR2), "dlopen changed the caller's signal mask");
        require(!pthread_sigmask(SIG_SETMASK, &original, nullptr), "cannot restore test signal mask");

        state.check = reinterpret_cast<Check>(stub_dlsym(module, "tls_concurrency_check"));
        state.verify = reinterpret_cast<Check>(stub_dlsym(module, "tls_concurrency_verify"));
        state.address = reinterpret_cast<Address>(stub_dlsym(module, "tls_concurrency_address"));
        require(state.check && state.verify && state.address, "module exports missing");
        require(!state.check(60) && !state.verify(60), "loading thread lost its TLS template");
        state.loaderAddress = state.address();
        return nullptr;
    }

    static Check runCase(const char* path, int mainValue) {
        State state = {};

        state.path = path;
        sem_t* semaphores[] = {&state.create, &state.copied, &state.resumeCopy, &state.load, &state.registration, &state.created, &state.ready};
        for (auto* semaphore : semaphores) {
            require(!sem_init(semaphore, 0, 0), "semaphore init failed");
        }
        require(!pthread_barrier_init(&state.writes, nullptr, 5), "barrier init failed");
        for (int index = 0; index < 4; ++index) {
            state.workers[index].state = &state;
            state.workers[index].value = 20 + index;
        }
        for (int index = 0; index < 2; ++index) {
            require(!pthread_create(&state.workers[index].thread, nullptr, workerMain, &state.workers[index]), "existing thread creation failed");
        }
        require(!pthread_create(&state.workers[2].thread, nullptr, creatorMain, &state), "creator thread setup failed");
        require(!pthread_create(&state.loader, nullptr, loaderMain, &state), "loader thread setup failed");
        __atomic_store_n(&active, &state, __ATOMIC_RELEASE);

        __atomic_store_n(&state.pauseCopy, 1, __ATOMIC_RELEASE);
        post(state.create);
        wait(state.copied);
        post(state.load);
        wait(state.registration);
        post(state.resumeCopy);
        wait(state.created);
        require(!pthread_join(state.loader, nullptr), "loader join failed");

        require(!state.check(mainValue), "main thread lost its TLS template");
        for (int index = 0; index < 4; ++index) {
            post(state.ready);
        }
        pthread_barrier_wait(&state.writes);
        for (auto& worker : state.workers) {
            require(!pthread_join(worker.thread, nullptr), "worker join failed");
        }
        require(!state.verify(mainValue), "workers changed the main thread's TLS");
        int* addresses[] = {state.address(), state.loaderAddress, state.workers[0].address, state.workers[1].address, state.workers[2].address, state.workers[3].address};
        for (int first = 0; first < 6; ++first) {
            for (int second = 0; second < first; ++second) {
                require(addresses[first] != addresses[second], "two threads share a TLS address");
            }
        }
        __atomic_store_n(&active, static_cast<State*>(nullptr), __ATOMIC_RELEASE);
        Worker future = {};

        future.state = &state;
        future.value = 70;
        require(!pthread_create(&future.thread, nullptr, futureMain, &future), "future thread creation failed");
        require(!pthread_join(future.thread, nullptr), "future thread join failed");
        require(future.address != state.address() && !state.verify(mainValue), "future thread changed the main thread's TLS");
        require(!pthread_barrier_destroy(&state.writes), "barrier destroy failed");
        for (auto* semaphore : semaphores) {
            require(!sem_destroy(semaphore), "semaphore destroy failed");
        }
        return state.verify;
    }
}

extern "C" void* __wrap___copy_tls(unsigned char* memory) {
    auto* result = __real___copy_tls(memory);
    auto* state = __atomic_load_n(&active, __ATOMIC_ACQUIRE);

    if (state && __atomic_exchange_n(&state->pauseCopy, 0, __ATOMIC_ACQ_REL)) {
        post(state->copied);
        wait(state->resumeCopy);
    }
    return result;
}

extern "C" int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t* lock) {
    if (auto* state = loadingState(); state) {
        // The paused pthread_create must already own the read side. Check
        // contention without a timeout before allowing it to join the ring.
        require(pthread_rwlock_trywrlock(lock) == EBUSY, "thread creation is not protected by the PTC lock");
        state->creationBlocked = true;
        post(state->registration);
    }
    return __real_pthread_rwlock_wrlock(lock);
}

extern "C" void __wrap___tl_lock() {
    __real___tl_lock();
    if (auto* state = loadingState(); state) {
        state->traversing = 1;
        ++state->traversals;
        require(!pthread_kill(pthread_self(), SIGUSR1), "cannot queue test signal");
    }
}

extern "C" void __wrap___tl_unlock() {
    __real___tl_unlock();
    if (auto* state = loadingState(); state) {
        state->traversing = 0;
    }
}

int main(int argc, char** argv) {
    require(argc == 3, "expected IE and GD module paths");
    struct sigaction action = {};
    struct sigaction previous;

    action.sa_handler = onSignal;
    sigemptyset(&action.sa_mask);
    require(!sigaction(SIGUSR1, &action, &previous), "sigaction failed");
    auto first = runCase(argv[1], 10);
    runCase(argv[2], 11);
    require(!first(10), "loading another module reset existing TLS");
    require(!sigaction(SIGUSR1, &previous, nullptr), "sigaction restore failed");
    puts("TLS concurrency: IE/GD, existing/creating/future threads, signals: ok");
}
