#include "thread_tls.h"

#include <pthread.h>
#include <stdlib.h>

#include <deque>
#include <string>
#include <utility>
#include <vector>

using namespace dyn;

// The C++ runtime's __cxa_thread_atexit fallback registers a static cleanup
// object against __dso_handle, which normally comes from crtbegin.o. The
// vendored -nostdlib link has no crtbegin.o and GNU ld does not synthesize
// the symbol, so define it here; weak, letting a host link's crtbegin.o win.
extern "C" __attribute__((weak, visibility("hidden"))) void* __dso_handle = nullptr;

namespace {
    struct State final: public ThreadTls {
        ~State();

        void registerDtor(void (*function)(void*), void* argument) override;
        void** tlsBlock(size_t module) override;

        void setDlError(std::string_view error) override;
        void clearDlError() override;
        char* takeDlError() override;

        void* tlsStub(size_t index, size_t size) override;
        void** nftwCallback() override;

        void drainDtors();

        std::vector<std::pair<void (*)(void*), void*>> dtors_;
        // A deque keeps the slot pointers tlsBlock() hands out stable while
        // the container grows.
        std::deque<void*> blocks_;
        std::vector<std::pair<size_t, void*>> stubs_;
        std::string dlError_;
        std::string takenDlError_;
        void* nftwCallback_ = nullptr;
    };

    static void threadExit(void* opaque) {
        delete static_cast<State*>(opaque);
    }
}

State::~State() {
    drainDtors();
    for (void* block : blocks_) {
        free(block);
    }
    for (const auto& stub : stubs_) {
        free(stub.second);
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

void State::setDlError(std::string_view error) {
    dlError_.assign(error);
}

void State::clearDlError() {
    dlError_.clear();
}

char* State::takeDlError() {
    if (dlError_.empty()) {
        return nullptr;
    }

    takenDlError_.swap(dlError_);
    dlError_.clear();

    return takenDlError_.data();
}

void* State::tlsStub(size_t index, size_t size) {
    for (const auto& stub : stubs_) {
        if (stub.first == index) {
            return stub.second;
        }
    }

    auto* storage = calloc(1, size);

    stubs_.emplace_back(index, storage);

    return storage;
}

void** State::nftwCallback() {
    return &nftwCallback_;
}

// The pthread key clears its value before running the destructor, so a
// thread-exit destructor that reaches back — a guest's own thread destructor
// touching another module's TLS — gets a fresh State, and the key machinery
// runs one more round for it.
ThreadTls* ThreadTls::current() {
    static const pthread_key_t key = [] {
        pthread_key_t created;

        if (pthread_key_create(&created, threadExit)) {
            abort();
        }

        return created;
    }();

    auto* state = static_cast<State*>(pthread_getspecific(key));

    if (!state) {
        state = new State();
        pthread_setspecific(key, state);
    }

    return state;
}
