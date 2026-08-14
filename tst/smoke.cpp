#include "dlfcn.h"
#include "elf_loader.h"

#include <memory>
#include <stdio.h>
#include <stdint.h>
#include <exception>

using EnumerateInstanceVersion = int32_t (*)(uint32_t* version);

int main() {
    auto* pci = stub_dlopen("libdlfcn-test-pci.so", RTLD_NOW | RTLD_LOCAL);

    if (!pci) {
        fprintf(stderr, "recursive load failed: %s\n", stub_dlerror());
        return 1;
    }
    if (!stub_dlsym(pci, "pci_system_init")) {
        fprintf(stderr, "libpciaccess lookup failed: %s\n", stub_dlerror());
        return 1;
    }

    std::unique_ptr<ElfImage> image;
    try {
        image.reset(ElfImage::loadElf("libdlfcn-test-vulkan.so", RTLD_NOW | RTLD_LOCAL));
    } catch (const std::exception& error) {
        fprintf(stderr, "load failed: %s\n", error.what());
        return 1;
    }

    auto enumerate = reinterpret_cast<EnumerateInstanceVersion>(image->lookup("vkEnumerateInstanceVersion"));

    if (!enumerate) {
        fprintf(stderr, "symbol lookup failed\n");
        return 1;
    }

    uint32_t version = 0;
    auto result = enumerate(&version);

    printf(
        "recursive DT_NEEDED: libpciaccess -> libz: ok\n"
        "vkEnumerateInstanceVersion: result=%d version=%u.%u.%u\n",
        result,
        version >> 22,
        (version >> 12) & 0x3ff,
        version & 0xfff
    );
    return result != 0;
}
