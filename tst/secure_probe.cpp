// The AT_SECURE probe: reports whether the kernel put the process in
// secure-execution mode and whether the loader honored the environment's
// search paths for a bare-name dlopen. run_secure.py runs it twice — plain,
// and set-uid root — and asserts the pairing.

#include "dlfcn.h"
#include "elf_loader.h"

#include <stdio.h>
#include <sys/auxv.h>

int main(int argumentCount, char** arguments) {
    dyn::init();
    if (argumentCount != 2) {
        fprintf(stderr, "usage: secure_probe LIBRARY\n");
        return 2;
    }

    auto* handle = stub_dlopen(arguments[1], RTLD_NOW | RTLD_LOCAL);

    printf("secure=%lu %s\n", getauxval(AT_SECURE), handle ? "loaded" : "not-loaded");

    return 0;
}
