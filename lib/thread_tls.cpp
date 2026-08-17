#if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
#endif

#include "thread_tls.h"

#include <stdlib.h>
#include <unistd.h>

#include <deque>
#include <utility>
#include <vector>

extern "C" int __cxa_thread_atexit(void (*function)(void*), void* argument, void* dso);

namespace {
    struct State final: public ThreadTls {
        ~State();

        void registerDtor(void (*function)(void*), void* argument) override;
        void** tlsBlock(size_t module) override;

        void drainDtors();

        std::vector<std::pair<void (*)(void*), void*>> dtors_;
        // A deque keeps the slot pointers tlsBlock() hands out stable while
        // the container grows.
        std::deque<void*> blocks_;
    };

    static void threadExit(void* opaque) {
        auto* state = static_cast<State*>(opaque);

        // The main thread reaches this from exit(), where atexit handlers of
        // loaded DSOs still run afterwards and still use their TLS. Keep the
        // state alive for them, like glibc keeps the main thread's DTV, and
        // let the process reclaim the memory.
        if (getpid() == gettid()) {
            state->drainDtors();
            return;
        }

        delete state;
    }
}

State::~State() {
    drainDtors();
    for (void* block : blocks_) {
        free(block);
    }
}

void State::drainDtors() {
    // LIFO, and a running destructor may register another one.
    while (!dtors_.empty()) {
        auto [function, argument] = dtors_.back();

        dtors_.pop_back();
        function(argument);
    }
}

void State::registerDtor(void (*function)(void*), void* argument) {
    dtors_.emplace_back(function, argument);
}

void** State::tlsBlock(size_t module) {
    if (module >= blocks_.size()) {
        blocks_.resize(module + 1);
    }

    return &blocks_[module];
}

ThreadTls* ThreadTls::current() {
    static thread_local State* state = nullptr;

    if (!state) {
        state = new State();
        __cxa_thread_atexit(threadExit, state, nullptr);
    }

    return state;
}
