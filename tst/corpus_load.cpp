#include "dlfcn.h"
#include "fault_report.h"

#include <stdio.h>

int main(int argc, char** argv) {
    stub_dlinit();
    installFaultReport();

    if (argc != 2) {
        fprintf(stderr, "usage: corpus_load LIBRARY\n");
        return 2;
    }
    if (!stub_dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)) {
        fprintf(stderr, "%s\n", stub_dlerror());
        return 1;
    }

    return 0;
}
