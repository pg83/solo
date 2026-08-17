#pragma once

/* A crash reporter for the test drivers: on a fatal signal, name the fault
 * address and the program counter through the loader's dladdr, so a CI-only
 * crash identifies its image and symbol without a debugger. */

#include "dlfcn.h"

#include <signal.h>
#include <stdio.h>
#include <ucontext.h>
#include <unistd.h>

static void faultReport(int signal_number, siginfo_t* information, void* context) {
    uintptr_t pc = 0;

#if defined(__x86_64__)
    pc = (uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[16];
#elif defined(__aarch64__)
    pc = (uintptr_t)((ucontext_t*)context)->uc_mcontext.pc;
#endif

    char line[512];
    Dl_info info = {0, 0, 0, 0};
    int length;

    if (stub_dladdr((void*)pc, &info) && info.dli_fname) {
        length = snprintf(line, sizeof(line), "solo test: signal %d at %p, pc %p (%s+0x%zx in %s)\n", signal_number, information->si_addr, (void*)pc, info.dli_sname ? info.dli_sname : "?", (size_t)(pc - (uintptr_t)(info.dli_saddr ? info.dli_saddr : info.dli_fbase)), info.dli_fname);
    } else {
        length = snprintf(line, sizeof(line), "solo test: signal %d at %p, pc %p\n", signal_number, information->si_addr, (void*)pc);
    }
    write(2, line, length > 0 ? (size_t)length : 0);
    _exit(128 + signal_number);
}

static void installFaultReport(void) {
    struct sigaction action;
    int signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};

    for (unsigned index = 0; index < sizeof(signals) / sizeof(signals[0]); ++index) {
        action.sa_sigaction = faultReport;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        sigaction(signals[index], &action, 0);
    }
}
