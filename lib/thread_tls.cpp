#include "thread_tls.h"

#include <stdlib.h>
#include <unistd.h>

#include <deque>
#include <string>
#include <utility>
#include <vector>

using namespace dyn;

extern "C" int __cxa_thread_atexit(void (*function)(void*), void* argument, void* dso);

namespace {
    struct State final: public ThreadTls {
        ~State();

        void registerDtor(void (*function)(void*), void* argument) override;
        void** tlsBlock(size_t module) override;

        void setDlError(std::string_view error) override;
        void clearDlError() override;
        char* takeDlError() override;

        void drainDtors();

        std::vector<std::pair<void (*)(void*), void*>> dtors_;
        // A deque keeps the slot pointers tlsBlock() hands out stable while
        // the container grows.
        std::deque<void*> blocks_;
        std::string dlError_;
        std::string takenDlError_;
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

ThreadTls* ThreadTls::current() {
    static thread_local State* state = nullptr;

    if (!state) {
        if (getpid() == gettid()) {
            static State* main = new State(); // never reclaimed
            state = main;
        } else {
            state = new State();
            __cxa_thread_atexit(threadExit, state, nullptr);
        }
    }

    return state;
}
