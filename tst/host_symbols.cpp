#include "dlfcn.h"

#define DLFCN_TEST_HOST_SYMBOLS(X) \
    X(__ctype_b_loc)               \
    X(__ctype_tolower_loc)         \
    X(__cxa_finalize)              \
    X(__errno_location)            \
    X(__stack_chk_fail)            \
    X(abort)                       \
    X(access)                      \
    X(calloc)                      \
    X(close)                       \
    X(closedir)                    \
    X(fclose)                      \
    X(fcntl)                       \
    X(fileno)                      \
    X(fopen)                       \
    X(fputc)                       \
    X(fputs)                       \
    X(fread)                       \
    X(free)                        \
    X(fstat)                       \
    X(fwrite)                      \
    X(getenv)                      \
    X(ioctl)                       \
    X(iopl)                        \
    X(malloc)                      \
    X(memchr)                      \
    X(memcpy)                      \
    X(memmove)                     \
    X(memset)                      \
    X(mprotect)                    \
    X(munmap)                      \
    X(open)                        \
    X(opendir)                     \
    X(qsort)                       \
    X(read)                        \
    X(readdir)                     \
    X(readlink)                    \
    X(realloc)                     \
    X(realpath)                    \
    X(secure_getenv)               \
    X(snprintf)                    \
    X(stderr)                      \
    X(strchr)                      \
    X(strcmp)                      \
    X(strdup)                      \
    X(strerror)                    \
    X(strlen)                      \
    X(strncat)                     \
    X(strncmp)                     \
    X(strncpy)                     \
    X(strrchr)                     \
    X(strstr)                      \
    X(strtod)                      \
    X(strtok_r)                    \
    X(write)

#define DLFCN_TEST_DECLARE_HOST_SYMBOL(symbol) extern "C" unsigned char DLFCN_TEST_HOST_##symbol[] __asm__(#symbol);

DLFCN_TEST_HOST_SYMBOLS(DLFCN_TEST_DECLARE_HOST_SYMBOL)

namespace {
    struct RegisterHostSymbols {
        RegisterHostSymbols() {
#define DLFCN_TEST_REGISTER_HOST_SYMBOL(symbol) stub_dlregister("c", #symbol, DLFCN_TEST_HOST_##symbol);

            DLFCN_TEST_HOST_SYMBOLS(DLFCN_TEST_REGISTER_HOST_SYMBOL)

#undef DLFCN_TEST_REGISTER_HOST_SYMBOL
        }
    } REGISTER_HOST_SYMBOLS;
}

#undef DLFCN_TEST_DECLARE_HOST_SYMBOL
#undef DLFCN_TEST_HOST_SYMBOLS
