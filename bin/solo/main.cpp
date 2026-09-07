// The solo command: run a ready-made dynamically linked glibc executable on
// the embedded musl and the ABI bridge, no host libc involved. The loader
// maps the executable and its closure, lib/enter.cpp builds the System V
// process stack, and the jump to the guest's own _start comes back into the
// bridge through the executable's __libc_start_main import.

#include "dlfcn.h"
#include "elf_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#include <exception>
#include <string>

using namespace dyn;

namespace {
    static int usage() {
        fprintf(stderr,
                "usage: solo [run] PROGRAM [ARGUMENTS...]\n"
                "       solo ldd PROGRAM\n");

        return 2;
    }

    // The PT_INTERP path: the kernel mapped the guest, mapped solo where the
    // guest's interpreter string pointed, and started solo with the guest's
    // own stack. The auxiliary vector describes the guest — headers, entry,
    // execution path — and stays valid for it, so after adoption the jump
    // reuses the kernel's stack unchanged: the word before argv is argc,
    // exactly where the guest's _start wants the stack pointer. Exits like
    // ld.so: 127 when the guest cannot be started.
    [[noreturn]] static void interpret(char** argv) {
        try {
            auto* headers = reinterpret_cast<const Elf64_Phdr*>(getauxval(AT_PHDR));
            auto count = static_cast<size_t>(getauxval(AT_PHNUM));
            auto* name = reinterpret_cast<const char*>(getauxval(AT_EXECFN));

            if (!name || !*name) {
                name = argv[0] ? argv[0] : "the kernel-mapped guest";
            }

            auto executable = adoptExecutable(name, headers, count, getauxval(AT_ENTRY));

            if (traceLoadedObjects()) {
                exit(0);
            }
            enterExecutableStack(executable.entry, reinterpret_cast<uintptr_t>(argv - 1));
        } catch (const std::exception& error) {
            fprintf(stderr, "solo: %s\n", error.what());
        } catch (...) {
            fprintf(stderr, "solo: unknown error\n");
        }
        exit(127);
    }
}

int main(int argc, char** argv) {
    // A nonzero AT_BASE is the interpreter's load base — the kernel only
    // publishes one when it loaded an interpreter, and then that interpreter
    // is this process's own image.
    if (getauxval(AT_BASE)) {
        interpret(argv);
    }

    // A payload appended to this very file makes solo the program's stub
    // rather than a command: there is nothing to parse, and argv belongs to
    // the guest exactly as it arrived.
    if (soloHasBundle()) {
        return soloBundleMain(argc, argv);
    }

    auto ldd = false;
    int consumed = 1;

    if (argc > 1 && (strcmp(argv[1], "run") == 0 || strcmp(argv[1], "ldd") == 0)) {
        ldd = strcmp(argv[1], "ldd") == 0;
        consumed = 2;
    }
    if (argc <= consumed) {
        return usage();
    }

    // Like execve, the program is a file path, not a library search: a bare
    // name means the current directory.
    std::string path = argv[consumed];

    if (path.find('/') == std::string::npos) {
        path.insert(0, "./");
    }

    try {
        if (ldd) {
            setenv("LD_TRACE_LOADED_OBJECTS", "1", 1);
        }

        auto executable = loadExecutable(path);

        // ldd mode, ld.so's way: whether through the subcommand or the
        // environment, the closure has printed and nothing runs.
        if (traceLoadedObjects()) {
            return 0;
        }

        enterExecutable(executable, path.c_str(), argc - consumed, argv + consumed);
    } catch (const std::exception& error) {
        fprintf(stderr, "solo: %s\n", error.what());
    } catch (...) {
        fprintf(stderr, "solo: unknown error\n");
    }

    return 127;
}
