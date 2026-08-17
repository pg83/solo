#pragma once

/* A crash reporter for the test drivers: on a fatal signal, name the fault
 * address, the program counter, and the frame-pointer chain through the
 * loader's dladdr, so a CI-only crash identifies its stack without a
 * debugger. The drivers are built with -fno-omit-frame-pointer, so the
 * chain is walkable; addresses inside the static executable have no dladdr
 * entry and are symbolized by the python driver against the binary. */

#include "dlfcn.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <ucontext.h>
#include <unistd.h>

static void faultReportLine(uintptr_t pc, const char* label) {
    char line[512];
    Dl_info info = {0, 0, 0, 0};
    int length;

    if (stub_dladdr((void*)pc, &info) && info.dli_fname) {
        length = snprintf(line, sizeof(line), "solo test: %s pc 0x%zx (%s+0x%zx in %s)\n", label, (size_t)pc, info.dli_sname ? info.dli_sname : "?", (size_t)(pc - (uintptr_t)(info.dli_saddr ? info.dli_saddr : info.dli_fbase)), info.dli_fname);
    } else {
        length = snprintf(line, sizeof(line), "solo test: %s pc 0x%zx\n", label, (size_t)pc);
    }
    write(2, line, length > 0 ? (size_t)length : 0);
}

static void faultReport(int signal_number, siginfo_t* information, void* context) {
    uintptr_t pc = 0;
    uintptr_t frame = 0;

#if defined(__x86_64__)
    pc = (uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[16];
    frame = (uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[10];
#elif defined(__aarch64__)
    pc = (uintptr_t)((ucontext_t*)context)->uc_mcontext.pc;
    frame = (uintptr_t)((ucontext_t*)context)->uc_mcontext.regs[29];
#endif

    /* The buffered "ok" lines of the sections already passed would die with
     * the process; the crash is not inside stdio often enough for this to be
     * worth the impurity. */
    fflush(stdout);

    char line[128];
    int length = snprintf(line, sizeof(line), "solo test: signal %d at %p\n", signal_number, information->si_addr);
    write(2, line, length > 0 ? (size_t)length : 0);

    faultReportLine(pc, "crash");

    /* Both ABIs store the caller's frame pointer at [fp] and the return
     * address at [fp + 8]. A garbage pointer here ends the walk with the
     * kernel's default SIGSEGV action; every line already written survives. */
    for (int depth = 0; depth < 16 && frame > 4096 && frame % sizeof(uintptr_t) == 0; ++depth) {
        uintptr_t return_address = ((uintptr_t*)frame)[1];

        if (!return_address) {
            break;
        }
#if defined(__aarch64__)
        /* Frames of pac-ret code keep a signed return address on the stack;
         * drop the authentication bits above the 48-bit address space. */
        return_address &= ((uintptr_t)1 << 48) - 1;
#endif
        faultReportLine(return_address, "frame");
        frame = ((uintptr_t*)frame)[0];
    }
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
