// The bridge defines _dl_find_object itself, with its own result type; hide the
// declaration a host <dlfcn.h> makes so the two cannot collide.
#define _dl_find_object sh_host_dl_find_object

#include "glibc_shim.h"

#include <link.h>

#include "dlfcn.h"
#include "elf_loader.h"
#include "fts.h"
#include "glibc_stubs.h"
#include "hash.h"
#include "thread_tls.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <glob.h>
#include <grp.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <langinfo.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <malloc.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <resolv.h>
#include <sched.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/auxv.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#include <algorithm>
#include <string>
#include <exception>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

using namespace dyn;

#undef _dl_find_object

extern "C" int __cxa_atexit(void (*function)(void*), void* argument, void* dso);
extern "C" void _Unwind_DeleteException();
extern "C" void _Unwind_GetDataRelBase();
extern "C" void _Unwind_GetIPInfo();
extern "C" void _Unwind_GetLanguageSpecificData();
extern "C" void _Unwind_GetRegionStart();
extern "C" void _Unwind_GetTextRelBase();
extern "C" void _Unwind_RaiseException();
extern "C" void _Unwind_Resume();
extern "C" void _Unwind_Resume_or_Rethrow();
extern "C" void _Unwind_SetGR();
extern "C" void _Unwind_SetIP();
// The two entry points backtrace() rides on, in the vendored
// libunwind's ABI; the block above only forwards addresses.
extern "C" int _Unwind_Backtrace(int (*step)(void*, void*), void* opaque);
extern "C" uintptr_t _Unwind_GetIP(void* context);
// The assembly halves in glibc_shim.S, against the glibc ucontext_t layout.
extern "C" int soloGetcontext(void* context);
extern "C" void soloSetcontext(void* context);
extern "C" int soloSwapcontext(void* saved, void* target);
extern "C" void soloStartContext();

#define SH_FUNCTION(name, version, function) {name, version, (void*)(uintptr_t)(function)}

#define SH_OBJECT(name, version, object) {name, version, (void*)(uintptr_t)(&(object))}

namespace {
    struct GlibcSymbol {
        const char* name;
        const char* version;
        void* address;
    };

    static void sh_fortify_fail(void) {
        fputs("glibc bridge: fortified operation overflow\n", stderr);
        abort();
    }

    static char* sh_strcat_chk(char* destination, const char* source, size_t size) {
        size_t destination_length = strlen(destination);
        size_t source_length = strlen(source);
        if (destination_length >= size || source_length >= size - destination_length) {
            sh_fortify_fail();
        }
        return strcat(destination, source);
    }

    static int sh_bcmp(const void* left, const void* right, size_t size) {
        return memcmp(left, right, size);
    }

    static char* sh_strerror_result(char* result, char*, size_t) {
        return result;
    }

    static char* sh_strerror_result(int result, char* buffer, size_t size) {
        if (result) {
            if (size) {
                buffer[0] = '\0';
            }
        }

        return buffer;
    }

    static char* sh_strerror_r(int error, char* buffer, size_t size) {
        return sh_strerror_result(strerror_r(error, buffer, size), buffer, size);
    }

    static int sh_snprintf_chk(char* destination, size_t count, int flag, size_t destination_size, const char* format, ...) {
        (void)flag;
        if (count > destination_size) {
            sh_fortify_fail();
        }
        va_list arguments;
        va_start(arguments, format);
        int result = vsnprintf(destination, count, format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_vsnprintf_chk(char* destination, size_t count, int flag, size_t destination_size, const char* format, va_list arguments) {
        (void)flag;
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return vsnprintf(destination, count, format, arguments);
    }

    static int sh_printf_chk(int flag, const char* format, ...) {
        (void)flag;
        va_list arguments;
        va_start(arguments, format);
        int result = vprintf(format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_fprintf_chk(FILE* stream, int flag, const char* format, ...) {
        (void)flag;
        va_list arguments;
        va_start(arguments, format);
        int result = vfprintf(stream, format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_vfprintf_chk(FILE* stream, int flag, const char* format, va_list arguments) {
        (void)flag;
        return vfprintf(stream, format, arguments);
    }

    static int sh_sprintf_chk(char* destination, int flag, size_t destination_size, const char* format, ...) {
        (void)flag;
        va_list arguments;
        va_start(arguments, format);
        int result = vsnprintf(destination, destination_size, format, arguments);
        va_end(arguments);
        if (result < 0 || (size_t)result >= destination_size) {
            sh_fortify_fail();
        }
        return result;
    }

    static int sh_vsprintf_chk(char* destination, int flag, size_t destination_size, const char* format, va_list arguments) {
        (void)flag;
        int result = vsnprintf(destination, destination_size, format, arguments);
        if (result < 0 || (size_t)result >= destination_size) {
            sh_fortify_fail();
        }
        return result;
    }

    static int sh_asprintf_chk(char** destination, int flag, const char* format, ...) {
        (void)flag;
        va_list arguments;
        va_start(arguments, format);
        int result = vasprintf(destination, format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_vasprintf_chk(char** destination, int flag, const char* format, va_list arguments) {
        (void)flag;
        return vasprintf(destination, format, arguments);
    }

    static void* sh_memcpy_chk(void* destination, const void* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return memcpy(destination, source, count);
    }

    static void* sh_memset_chk(void* destination, int value, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return memset(destination, value, count);
    }

    static void* sh_memmove_chk(void* destination, const void* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return memmove(destination, source, count);
    }

    static size_t sh_fread_chk(void* destination, size_t destination_size, size_t element_size, size_t element_count, FILE* stream) {
        if (element_size && element_count > destination_size / element_size) {
            sh_fortify_fail();
        }
        return fread(destination, element_size, element_count, stream);
    }

    static char* sh_strncpy_chk(char* destination, const char* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return strncpy(destination, source, count);
    }

    static char* sh_strncat_chk(char* destination, const char* source, size_t count, size_t destination_size) {
        size_t destination_length = strlen(destination);
        size_t source_length = strnlen(source, count);
        if (destination_length >= destination_size || source_length >= destination_size - destination_length) {
            sh_fortify_fail();
        }
        return strncat(destination, source, count);
    }

    static char* sh_strcpy_chk(char* destination, const char* source, size_t destination_size) {
        size_t size = strlen(source) + 1;
        if (size > destination_size) {
            sh_fortify_fail();
        }
        return static_cast<char*>(memcpy(destination, source, size));
    }

    static size_t sh_strlcpy_chk(char* destination, const char* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return strlcpy(destination, source, count);
    }

    static ssize_t sh_read_chk(int descriptor, void* destination, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return read(descriptor, destination, count);
    }

    static ssize_t sh_pread_chk(int descriptor, void* destination, size_t count, off_t offset, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return pread(descriptor, destination, count, offset);
    }

    static ssize_t sh_readlinkat_chk(int directory, const char* path, char* destination, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return readlinkat(directory, path, destination, count);
    }

    static char* sh_realpath_chk(const char* path, char* destination, size_t destination_size) {
        char* temporary = realpath(path, NULL);
        if (!temporary) {
            return NULL;
        }
        size_t size = strlen(temporary) + 1;
        if (size > destination_size) {
            free(temporary);
            sh_fortify_fail();
        }
        memcpy(destination, temporary, size);
        free(temporary);
        return destination;
    }

    static void sh_explicit_bzero_chk(void* destination, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        volatile unsigned char* bytes = static_cast<volatile unsigned char*>(destination);
        while (count--) {
            *bytes++ = 0;
        }
    }

    static size_t sh_mbsrtowcs_chk(wchar_t* destination, const char** source, size_t count, mbstate_t* state, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return mbsrtowcs(destination, source, count, state);
    }

    static size_t sh_mbstowcs_chk(wchar_t* destination, const char* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return mbstowcs(destination, source, count);
    }

    static wchar_t* sh_wcsncpy_chk(wchar_t* destination, const wchar_t* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return wcsncpy(destination, source, count);
    }

    static wchar_t* sh_wmemcpy_chk(wchar_t* destination, const wchar_t* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return wmemcpy(destination, source, count);
    }

    static wchar_t* sh_wmemset_chk(wchar_t* destination, wchar_t value, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return wmemset(destination, value, count);
    }

    static unsigned long sh_isoc23_strtoul(const char* text, char** end, int base) {
        return strtoul(text, end, base);
    }

    static long sh_isoc23_strtol(const char* text, char** end, int base) {
        return strtol(text, end, base);
    }

    static int sh_isoc23_sscanf(const char* text, const char* format, ...) {
        va_list arguments;
        va_start(arguments, format);
        int result = vsscanf(text, format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_isoc23_fscanf(FILE* stream, const char* format, ...) {
        va_list arguments;
        va_start(arguments, format);
        int result = vfscanf(stream, format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_isoc23_scanf(const char* format, ...) {
        va_list arguments;
        va_start(arguments, format);
        int result = vscanf(format, arguments);
        va_end(arguments);
        return result;
    }

    static int sh_isoc23_vsscanf(const char* text, const char* format, va_list arguments) {
        return vsscanf(text, format, arguments);
    }

    static long long sh_isoc23_strtoll(const char* text, char** end, int base) {
        return strtoll(text, end, base);
    }

    static unsigned long long sh_isoc23_strtoull(const char* text, char** end, int base) {
        return strtoull(text, end, base);
    }

    static long sh_isoc23_wcstol(const wchar_t* text, wchar_t** end, int base) {
        return wcstol(text, end, base);
    }

    static char* sh_secure_getenv(const char* name) {
        if (getuid() != geteuid() || getgid() != getegid()) {
            return NULL;
        }
        return getenv(name);
    }

    static void sh_arc4random_buf(void* buffer, size_t size) {
        unsigned char* cursor = static_cast<unsigned char*>(buffer);
        while (size) {
            ssize_t result = getrandom(cursor, size, 0);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                fputs("glibc bridge: getrandom failed\n", stderr);
                abort();
            }
            cursor += (size_t)result;
            size -= (size_t)result;
        }
    }

    static uint32_t sh_arc4random(void) {
        uint32_t result;
        sh_arc4random_buf(&result, sizeof(result));
        return result;
    }

    static int* sh_errno_location(void) {
        return &errno;
    }

    static long sh_fdelt_chk(long descriptor) {
        if (descriptor < 0 || descriptor >= FD_SETSIZE) {
            sh_fortify_fail();
        }
        return descriptor / (8 * (long)sizeof(long));
    }

    static char* sh_fgets_chk(char* destination, size_t destination_size, int count, FILE* stream) {
        if (count > 0 && (size_t)count > destination_size) {
            sh_fortify_fail();
        }
        return fgets(destination, count, stream);
    }

    static char* sh_getcwd_chk(char* destination, size_t size, size_t destination_size) {
        if (size > destination_size) {
            sh_fortify_fail();
        }
        return getcwd(destination, size);
    }

    static int sh_getgroups_chk(int count, gid_t* groups, size_t destination_size) {
        if (count > 0 && (size_t)count * sizeof(gid_t) > destination_size) {
            sh_fortify_fail();
        }
        return getgroups(count, groups);
    }

    static int sh_inet_pton_chk(int family, const char* source, void* destination, size_t destination_size) {
        if ((family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)) > destination_size) {
            sh_fortify_fail();
        }
        return inet_pton(family, source, destination);
    }

    static void* sh_mempcpy_chk(void* destination, const void* source, size_t count, size_t destination_size) {
        if (count > destination_size) {
            sh_fortify_fail();
        }
        return mempcpy(destination, source, count);
    }

    static int sh_poll_chk(struct pollfd* descriptors, nfds_t count, int timeout, size_t destination_size) {
        if (count * sizeof(struct pollfd) > destination_size) {
            sh_fortify_fail();
        }
        return poll(descriptors, count, timeout);
    }

    static char* sh_stpcpy_chk(char* destination, const char* source, size_t destination_size) {
        if (strlen(source) + 1 > destination_size) {
            sh_fortify_fail();
        }
        return stpcpy(destination, source);
    }

    static void sh_vsyslog_chk(int priority, int flag, const char* format, va_list arguments) {
        (void)flag;
        vsyslog(priority, format, arguments);
    }

    static intmax_t sh_isoc23_strtoimax(const char* text, char** end, int base) {
        return strtoimax(text, end, base);
    }

    static uintmax_t sh_isoc23_strtoumax(const char* text, char** end, int base) {
        return strtoumax(text, end, base);
    }

    static long long sh_isoc23_strtoll_l(const char* text, char** end, int base, void* locale) {
        (void)locale;
        return strtoll(text, end, base);
    }

    static unsigned long long sh_isoc23_strtoull_l(const char* text, char** end, int base, void* locale) {
        (void)locale;
        return strtoull(text, end, base);
    }

    static int sh_isoc23_vfscanf(FILE* stream, const char* format, va_list arguments) {
        return vfscanf(stream, format, arguments);
    }

    // The vendored musl predates close_range(); raw syscalls, like the new
    // mount API below.
    static int sh_close_range(unsigned first, unsigned last, int flags) {
        return (int)syscall(436, first, last, flags);
    }

    static void sh_closefrom(int first) {
        syscall(436, first < 0 ? 0u : (unsigned)first, ~0u, 0);
    }

    static int sh_open_tree(int directory, const char* path, unsigned flags) {
        return (int)syscall(428, directory, path, flags);
    }

    static int sh_move_mount(int from_directory, const char* from_path, int to_directory, const char* to_path, unsigned flags) {
        return (int)syscall(429, from_directory, from_path, to_directory, to_path, flags);
    }

    static int sh_fsopen(const char* filesystem, unsigned flags) {
        return (int)syscall(430, filesystem, flags);
    }

    static int sh_fsconfig(int descriptor, unsigned command, const char* key, const void* value, int auxiliary) {
        return (int)syscall(431, descriptor, command, key, value, auxiliary);
    }

    static int sh_fsmount(int descriptor, unsigned flags, unsigned attributes) {
        return (int)syscall(432, descriptor, flags, attributes);
    }

    static int sh_fspick(int directory, const char* path, unsigned flags) {
        return (int)syscall(433, directory, path, flags);
    }

    static int sh_mount_setattr(int directory, const char* path, unsigned flags, void* attributes, size_t size) {
        return (int)syscall(442, directory, path, flags, attributes, size);
    }

    static int sh_pidfd_open(int pid, unsigned flags) {
        return (int)syscall(434, pid, flags);
    }

    // The libmvec lanes the corpus demands, split into scalar musl calls:
    // correctness over vector speed. The 128-bit vector types match both the
    // x86-64 'b' (SSE) and the aarch64 'n' (AdvSIMD) vector ABIs.
    typedef double VectorDouble2 __attribute__((vector_size(16)));
    typedef float VectorFloat4 __attribute__((vector_size(16)));

    static VectorDouble2 sh_vector_cos(VectorDouble2 value) {
        return VectorDouble2{cos(value[0]), cos(value[1])};
    }

    static VectorDouble2 sh_vector_sin(VectorDouble2 value) {
        return VectorDouble2{sin(value[0]), sin(value[1])};
    }

    static VectorDouble2 sh_vector_log(VectorDouble2 value) {
        return VectorDouble2{log(value[0]), log(value[1])};
    }

    static VectorDouble2 sh_vector_log2(VectorDouble2 value) {
        return VectorDouble2{log2(value[0]), log2(value[1])};
    }

    static VectorFloat4 sh_vector_cosf(VectorFloat4 value) {
        return VectorFloat4{cosf(value[0]), cosf(value[1]), cosf(value[2]), cosf(value[3])};
    }

    static VectorFloat4 sh_vector_sinf(VectorFloat4 value) {
        return VectorFloat4{sinf(value[0]), sinf(value[1]), sinf(value[2]), sinf(value[3])};
    }

    static VectorFloat4 sh_vector_acosf(VectorFloat4 value) {
        return VectorFloat4{acosf(value[0]), acosf(value[1]), acosf(value[2]), acosf(value[3])};
    }

    static VectorFloat4 sh_vector_logf(VectorFloat4 value) {
        return VectorFloat4{logf(value[0]), logf(value[1]), logf(value[2]), logf(value[3])};
    }

    static VectorFloat4 sh_vector_expf(VectorFloat4 value) {
        return VectorFloat4{expf(value[0]), expf(value[1]), expf(value[2]), expf(value[3])};
    }

    // backtrace over the static world's own unwinder: real frames, not a
    // stub. The symbols come from the loader's dladdr.
    struct BacktraceState {
        void** buffer;
        int size;
        int count;
    };

    static int backtraceStep(void* context, void* opaque) {
        auto* state = static_cast<BacktraceState*>(opaque);

        // 4 is _URC_NORMAL_STOP, 0 is _URC_NO_REASON.
        if (state->count >= state->size) {
            return 4;
        }
        state->buffer[state->count++] = reinterpret_cast<void*>(_Unwind_GetIP(context));

        return 0;
    }

    static int sh_backtrace(void** buffer, int size) {
        BacktraceState state{buffer, size, 0};

        if (size > 0) {
            _Unwind_Backtrace(backtraceStep, &state);
        }

        return state.count;
    }

    static size_t backtraceLine(char* text, size_t size, void* address) {
        Dl_info info{};

        if (stub_dladdr(address, &info) && info.dli_fname && info.dli_sname) {
            return snprintf(text, size, "%s(%s+0x%zx) [%p]", info.dli_fname, info.dli_sname, (size_t)((char*)address - (char*)info.dli_saddr), address);
        }
        if (stub_dladdr(address, &info) && info.dli_fname) {
            return snprintf(text, size, "%s(+0x%zx) [%p]", info.dli_fname, (size_t)((char*)address - (char*)info.dli_fbase), address);
        }

        return snprintf(text, size, "[%p]", address);
    }

    static char** sh_backtrace_symbols(void* const* buffer, int size) {
        size_t total = size * sizeof(char*);

        for (int index = 0; index < size; ++index) {
            total += backtraceLine(nullptr, 0, buffer[index]) + 1;
        }

        auto** lines = static_cast<char**>(malloc(total));

        if (!lines) {
            return nullptr;
        }

        auto* text = reinterpret_cast<char*>(lines + size);
        auto* end = reinterpret_cast<char*>(lines) + total;

        for (int index = 0; index < size; ++index) {
            lines[index] = text;
            text += backtraceLine(text, end - text, buffer[index]) + 1;
        }

        return lines;
    }

    static void sh_backtrace_symbols_fd(void* const* buffer, int size, int descriptor) {
        for (int index = 0; index < size; ++index) {
            char line[512];
            auto length = backtraceLine(line, sizeof(line) - 1, buffer[index]);

            line[length < sizeof(line) - 1 ? length : sizeof(line) - 2] = '\n';
            write(descriptor, line, (length < sizeof(line) - 1 ? length : sizeof(line) - 2) + 1);
        }
    }

    // The rest of the fortified family the corpus demands; the checked sizes
    // are the compiler's business, the calls forward to musl.
    static int sh_dprintf_chk(int descriptor, int flag, const char* format, ...) {
        (void)flag;

        va_list arguments;

        va_start(arguments, format);

        auto result = vdprintf(descriptor, format, arguments);

        va_end(arguments);

        return result;
    }

    static int sh_vdprintf_chk(int descriptor, int flag, const char* format, va_list arguments) {
        (void)flag;
        return vdprintf(descriptor, format, arguments);
    }

    static int sh_vprintf_chk(int flag, const char* format, va_list arguments) {
        (void)flag;
        return vprintf(format, arguments);
    }

    static int sh_swprintf_chk(wchar_t* text, size_t count, int flag, size_t size, const wchar_t* format, ...) {
        (void)flag;
        (void)size;

        va_list arguments;

        va_start(arguments, format);

        auto result = vswprintf(text, count, format, arguments);

        va_end(arguments);

        return result;
    }

    static int sh_vswprintf_chk(wchar_t* text, size_t count, int flag, size_t size, const wchar_t* format, va_list arguments) {
        (void)flag;
        (void)size;
        return vswprintf(text, count, format, arguments);
    }

    static int sh_wctomb_chk(char* text, wchar_t character, size_t size) {
        (void)size;
        return wctomb(text, character);
    }

    static ssize_t sh_readlink_chk(const char* path, char* buffer, size_t length, size_t size) {
        (void)size;
        return readlink(path, buffer, length);
    }

    static ssize_t sh_recv_chk(int descriptor, void* buffer, size_t length, size_t size, int flags) {
        (void)size;
        return recv(descriptor, buffer, length, flags);
    }

    static ssize_t sh_recvfrom_chk(int descriptor, void* buffer, size_t length, size_t size, int flags, struct sockaddr* address, socklen_t* addressLength) {
        (void)size;
        return recvfrom(descriptor, buffer, length, flags, address, addressLength);
    }

    static int sh_gethostname_chk(char* name, size_t length, size_t size) {
        (void)size;
        return gethostname(name, length);
    }

    static const char* sh_inet_ntop_chk(int family, const void* source, char* destination, socklen_t length, size_t size) {
        (void)size;
        return inet_ntop(family, source, destination, length);
    }

    // File and process plumbing musl spells without the 64 suffix or leaves
    // to raw syscalls.
    static ssize_t sh_sendfile64(int destination, int source, off_t* offset, size_t count) {
        return sendfile(destination, source, offset, count);
    }

    static int sh_renameat2(int fromDirectory, const char* from, int toDirectory, const char* to, unsigned flags) {
        return (int)syscall(SYS_renameat2, fromDirectory, from, toDirectory, to, flags);
    }

    static int sh_prlimit64(pid_t pid, int resource, const struct rlimit* fresh, struct rlimit* old) {
        return prlimit(pid, resource, fresh, old);
    }

    static int sh_truncate64(const char* path, off_t length) {
        return truncate(path, length);
    }

    static FILE* sh_tmpfile64(void) {
        return tmpfile();
    }

    static ssize_t sh_pwritev64(int descriptor, const struct iovec* vector, int count, off_t offset) {
        return pwritev(descriptor, vector, count, offset);
    }

    static int sh_readdir64_r(DIR* directory, struct dirent* entry, struct dirent** result) {
        return readdir_r(directory, entry, result);
    }

    static ssize_t sh_getdents64(int descriptor, void* buffer, size_t size) {
        return syscall(SYS_getdents64, descriptor, buffer, size);
    }

    static char* sh_canonicalize_file_name(const char* path) {
        return realpath(path, nullptr);
    }

    static int sh_pidfd_getpid(int descriptor) {
        char path[64];
        char text[256];

        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", descriptor);

        auto* stream = fopen(path, "r");

        if (!stream) {
            return -1;
        }

        int pid = -1;

        while (fgets(text, sizeof(text), stream)) {
            if (sscanf(text, "Pid: %d", &pid) == 1) {
                break;
            }
        }
        fclose(stream);
        if (pid <= 0) {
            errno = EBADF;
            return -1;
        }

        return pid;
    }

    // The spawned child stays unreaped until the caller sees the pidfd, so
    // opening it by pid after posix_spawnp cannot race a reuse.
    static int sh_pidfd_spawnp(int* descriptor, const char* file, void* fileActions, void* attributes, char* const argv[], char* const envp[]) {
        pid_t pid = 0;
        auto result = posix_spawnp(&pid, file, static_cast<posix_spawn_file_actions_t*>(fileActions), static_cast<posix_spawnattr_t*>(attributes), argv, envp);

        if (result) {
            return result;
        }

        auto opened = (int)syscall(434, pid, 0);

        if (opened < 0) {
            return errno;
        }
        *descriptor = opened;

        return 0;
    }

    static int sh_pkey_alloc(unsigned flags, unsigned rights) {
        return (int)syscall(SYS_pkey_alloc, flags, rights);
    }

    static int sh_pkey_free(int key) {
        return (int)syscall(SYS_pkey_free, key);
    }

    static int sh_pkey_mprotect(void* address, size_t length, int protection, int key) {
        return (int)syscall(SYS_pkey_mprotect, address, length, protection, key);
    }

    static int sh_pkey_set(int key, unsigned rights) {
#if defined(__x86_64__)
        unsigned mask = 3u << (2 * key);
        unsigned value;

        __asm__ volatile("xor %%ecx, %%ecx\n\trdpkru" : "=a"(value) : : "rcx", "rdx");
        value = (value & ~mask) | (rights << (2 * key));
        __asm__ volatile("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\twrpkru" : : "a"(value) : "rcx", "rdx");

        return 0;
#else
        (void)key;
        (void)rights;
        errno = ENOSYS;

        return -1;
#endif
    }

    static int sh_pkey_get(int key) {
#if defined(__x86_64__)
        unsigned value;

        __asm__ volatile("xor %%ecx, %%ecx\n\trdpkru" : "=a"(value) : : "rcx", "rdx");

        return (value >> (2 * key)) & 3;
#else
        (void)key;
        errno = ENOSYS;

        return -1;
#endif
    }

    // musl's glob_t already has the 64-bit layout glibc calls glob64_t.
    static int sh_glob64(const char* pattern, int flags, int (*failed)(const char*, int), glob_t* result) {
        return glob(pattern, flags, failed, result);
    }

    static void sh_globfree64(glob_t* result) {
        globfree(result);
    }

    static int sh_glob_pattern_p(const char* pattern, int quote) {
        for (const char* character = pattern; *character; ++character) {
            if (*character == '*' || *character == '?' || *character == '[') {
                return 1;
            }
            if (quote && *character == '\\' && character[1]) {
                ++character;
            }
        }

        return 0;
    }

    static int sh_isnanf(float value) {
        return isnan(value);
    }

    static int sh_isinff(float value) {
        return isinf(value);
    }

    static double sh_gamma(double value) {
        return lgamma(value);
    }

#if defined(__x86_64__)
    typedef __float128 Float128;
#else
    // On aarch64 long double already is binary128.
    typedef long double Float128;
#endif

    // On aarch64 long double is binary128, so these are exact. On x86-64
    // they round through double, converted by hand in integer arithmetic:
    // the vendored compiler-rt has no binary128 helpers where long double is
    // the 80-bit x87 type. The honest best without a native converter.
#if defined(__x86_64__)
    static Float128 extendedDouble(double from) {
        uint64_t bits;

        memcpy(&bits, &from, sizeof(bits));

        unsigned __int128 sign = (unsigned __int128)(bits >> 63) << 127;
        auto exponent = (int64_t)((bits >> 52) & 0x7ff);
        unsigned __int128 fraction = bits & ((1ull << 52) - 1);
        unsigned __int128 packed;

        if (exponent == 0x7ff) {
            // Infinity or NaN keeps its payload at the top of the fraction.
            packed = sign | ((unsigned __int128)0x7fff << 112) | (fraction << 60);
        } else if (exponent == 0 && !fraction) {
            packed = sign;
        } else {
            if (exponent == 0) {
                // A subnormal double normalizes in binary128's wider range.
                auto lead = 63 - __builtin_clzll((uint64_t)fraction);

                exponent = lead - 51;
                fraction = (fraction << (52 - lead)) & (((unsigned __int128)1 << 52) - 1);
            }
            packed = sign | ((unsigned __int128)(exponent - 1023 + 16383) << 112) | (fraction << 60);
        }

        Float128 value;

        memcpy(&value, &packed, sizeof(value));

        return value;
    }

    static double truncatedBinary128(Float128 from) {
        unsigned __int128 bits;

        memcpy(&bits, &from, sizeof(bits));

        uint64_t sign = (uint64_t)(bits >> 127) << 63;
        auto exponent = (int64_t)((bits >> 112) & 0x7fff);
        auto fraction = bits & (((unsigned __int128)1 << 112) - 1);
        uint64_t packed;

        if (exponent == 0x7fff) {
            packed = sign | (0x7ffull << 52) | (fraction ? 1ull << 51 : 0);
        } else {
            auto rebased = exponent - 16383 + 1023;
            auto mantissa = fraction | ((unsigned __int128)(exponent != 0) << 112);
            // Keep 53 bits: shift by 60 for normals, more into the double's
            // subnormal range, rounding to nearest even.
            auto shift = rebased > 0 ? 60 : 60 + 1 - rebased;

            if (rebased >= 0x7ff) {
                packed = sign | (0x7ffull << 52);
            } else if (shift > 114) {
                packed = sign;
            } else {
                auto kept = (uint64_t)(mantissa >> shift);
                auto rest = mantissa & (((unsigned __int128)1 << shift) - 1);
                auto half = (unsigned __int128)1 << (shift - 1);

                if (rest > half || (rest == half && (kept & 1))) {
                    ++kept;
                }
                if (rebased <= 0 && kept >> 53) {
                    ++rebased;
                    kept >>= 1;
                }
                if (kept >> 53) {
                    ++rebased;
                    kept >>= 1;
                }
                packed = sign | ((uint64_t)(rebased > 0 ? rebased : 0) << 52) | (kept & ((1ull << 52) - 1));
            }
        }

        double value;

        memcpy(&value, &packed, sizeof(value));

        return value;
    }
#endif

    static Float128 sh_strtof128(const char* text, char** end) {
#if defined(__aarch64__)
        return strtold(text, end);
#else
        return extendedDouble(strtod(text, end));
#endif
    }

    static Float128 sh_logf128(Float128 value) {
#if defined(__aarch64__)
        return logl((long double)value);
#else
        return extendedDouble(log(truncatedBinary128(value)));
#endif
    }

    static int sh_strfromf128(char* buffer, size_t size, const char* format, Float128 value) {
        // The strfrom format is '%', optional precision, one conversion
        // letter; reinsert it with the matching length modifier.
        char shape[32];
        auto length = strlen(format);

        if (length < 2 || length > sizeof(shape) - 2 || format[0] != '%') {
            errno = EINVAL;
            return -1;
        }
#if defined(__aarch64__)
        memcpy(shape, format, length - 1);
        shape[length - 1] = 'L';
        shape[length] = format[length - 1];
        shape[length + 1] = 0;

        return snprintf(buffer, size, shape, (long double)value);
#else
        memcpy(shape, format, length + 1);

        return snprintf(buffer, size, shape, truncatedBinary128(value));
#endif
    }

    // A per-caller-state generator behind glibc's random_r API: only these
    // functions ever touch the caller's state buffer, so its contents are
    // ours; splitmix over the buffer beats faking glibc's TYPE_x layouts.
    struct GlibcRandomData {
        uint64_t* state;
    };

    static int sh_initstate_r(unsigned seed, char* state, size_t size, GlibcRandomData* data) {
        if (!state || size < sizeof(uint64_t) || !data) {
            errno = EINVAL;
            return -1;
        }
        data->state = reinterpret_cast<uint64_t*>(state);
        *data->state = seed ? seed : 1;

        return 0;
    }

    static int sh_random_r(GlibcRandomData* data, int32_t* result) {
        if (!data || !data->state || !result) {
            errno = EINVAL;
            return -1;
        }

        auto value = *data->state;

        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *data->state = value;
        *result = (int32_t)(value >> 33);

        return 0;
    }

    static int sh_srandom_r(unsigned seed, GlibcRandomData* data) {
        if (!data || !data->state) {
            errno = EINVAL;
            return -1;
        }
        *data->state = seed ? seed : 1;

        return 0;
    }

    // The _r database wrappers copy musl's static results into the caller's
    // buffer, which is the whole of the _r contract.
    static char* placeString(const char* text, char** cursor, char* end) {
        auto length = strlen(text) + 1;

        if (*cursor + length > end) {
            return nullptr;
        }

        auto* placed = *cursor;

        memcpy(placed, text, length);
        *cursor += length;

        return placed;
    }

    static char** placeStrings(char* const* list, char** cursor, char* end) {
        size_t count = 0;

        while (list[count]) {
            ++count;
        }

        auto misalignment = reinterpret_cast<uintptr_t>(*cursor) % sizeof(char*);

        if (misalignment) {
            *cursor += sizeof(char*) - misalignment;
        }

        auto** placed = reinterpret_cast<char**>(*cursor);

        *cursor += (count + 1) * sizeof(char*);
        if (*cursor > end) {
            return nullptr;
        }
        for (size_t index = 0; index < count; ++index) {
            if (!(placed[index] = placeString(list[index], cursor, end))) {
                return nullptr;
            }
        }
        placed[count] = nullptr;

        return placed;
    }

    static int placeProtoent(const struct protoent* source, struct protoent* destination, char* buffer, size_t size, struct protoent** result) {
        *result = nullptr;
        if (!source) {
            return 0;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->p_proto = source->p_proto;
        if (!(destination->p_name = placeString(source->p_name, &cursor, end)) || !(destination->p_aliases = placeStrings(source->p_aliases, &cursor, end))) {
            return ERANGE;
        }
        *result = destination;

        return 0;
    }

    static int sh_getprotobyname_r(const char* name, struct protoent* destination, char* buffer, size_t size, struct protoent** result) {
        return placeProtoent(getprotobyname(name), destination, buffer, size, result);
    }

    static int sh_getprotobynumber_r(int number, struct protoent* destination, char* buffer, size_t size, struct protoent** result) {
        return placeProtoent(getprotobynumber(number), destination, buffer, size, result);
    }

    static int sh_getprotoent_r(struct protoent* destination, char* buffer, size_t size, struct protoent** result) {
        return placeProtoent(getprotoent(), destination, buffer, size, result);
    }

    static int sh_getservent_r(struct servent* destination, char* buffer, size_t size, struct servent** result) {
        auto* source = getservent();

        *result = nullptr;
        if (!source) {
            return 0;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->s_port = source->s_port;
        if (!(destination->s_name = placeString(source->s_name, &cursor, end)) || !(destination->s_proto = placeString(source->s_proto, &cursor, end)) || !(destination->s_aliases = placeStrings(source->s_aliases, &cursor, end))) {
            return ERANGE;
        }
        *result = destination;

        return 0;
    }

    static int placeNetent(const struct netent* source, struct netent* destination, char* buffer, size_t size, struct netent** result, int* herror) {
        *result = nullptr;
        if (herror) {
            *herror = HOST_NOT_FOUND;
        }
        if (!source) {
            return 0;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->n_addrtype = source->n_addrtype;
        destination->n_net = source->n_net;
        if (!(destination->n_name = placeString(source->n_name, &cursor, end)) || !(destination->n_aliases = placeStrings(source->n_aliases, &cursor, end))) {
            return ERANGE;
        }
        *result = destination;

        return 0;
    }

    static int sh_getnetent_r(struct netent* destination, char* buffer, size_t size, struct netent** result, int* herror) {
        return placeNetent(getnetent(), destination, buffer, size, result, herror);
    }

    static int sh_getnetbyname_r(const char* name, struct netent* destination, char* buffer, size_t size, struct netent** result, int* herror) {
        return placeNetent(getnetbyname(name), destination, buffer, size, result, herror);
    }

    static int sh_getnetbyaddr_r(uint32_t net, int type, struct netent* destination, char* buffer, size_t size, struct netent** result, int* herror) {
        return placeNetent(getnetbyaddr(net, type), destination, buffer, size, result, herror);
    }

    static int sh_gethostent_r(struct hostent* destination, char* buffer, size_t size, struct hostent** result, int* herror) {
        auto* source = gethostent();

        *result = nullptr;
        if (herror) {
            *herror = HOST_NOT_FOUND;
        }
        if (!source) {
            return 0;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->h_addrtype = source->h_addrtype;
        destination->h_length = source->h_length;
        if (!(destination->h_name = placeString(source->h_name, &cursor, end)) || !(destination->h_aliases = placeStrings(source->h_aliases, &cursor, end))) {
            return ERANGE;
        }

        size_t addresses = 0;

        while (source->h_addr_list[addresses]) {
            ++addresses;
        }

        auto misalignment = reinterpret_cast<uintptr_t>(cursor) % sizeof(char*);

        cursor += misalignment ? sizeof(char*) - misalignment : 0;
        destination->h_addr_list = reinterpret_cast<char**>(cursor);
        cursor += (addresses + 1) * sizeof(char*);
        if (cursor + addresses * source->h_length > end) {
            return ERANGE;
        }
        for (size_t index = 0; index < addresses; ++index) {
            destination->h_addr_list[index] = cursor;
            memcpy(cursor, source->h_addr_list[index], source->h_length);
            cursor += source->h_length;
        }
        destination->h_addr_list[addresses] = nullptr;
        *result = destination;

        return 0;
    }

    static int sh_getpwent_r(struct passwd* destination, char* buffer, size_t size, struct passwd** result) {
        auto* source = getpwent();

        *result = nullptr;
        if (!source) {
            return ENOENT;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->pw_uid = source->pw_uid;
        destination->pw_gid = source->pw_gid;
        if (!(destination->pw_name = placeString(source->pw_name, &cursor, end)) || !(destination->pw_passwd = placeString(source->pw_passwd ? source->pw_passwd : "", &cursor, end)) || !(destination->pw_gecos = placeString(source->pw_gecos ? source->pw_gecos : "", &cursor, end)) || !(destination->pw_dir = placeString(source->pw_dir, &cursor, end)) || !(destination->pw_shell = placeString(source->pw_shell, &cursor, end))) {
            return ERANGE;
        }
        *result = destination;

        return 0;
    }

    static int sh_getgrent_r(struct group* destination, char* buffer, size_t size, struct group** result) {
        auto* source = getgrent();

        *result = nullptr;
        if (!source) {
            return ENOENT;
        }

        auto* cursor = buffer;
        auto* end = buffer + size;

        destination->gr_gid = source->gr_gid;
        if (!(destination->gr_name = placeString(source->gr_name, &cursor, end)) || !(destination->gr_passwd = placeString(source->gr_passwd ? source->gr_passwd : "", &cursor, end)) || !(destination->gr_mem = placeStrings(source->gr_mem, &cursor, end))) {
            return ERANGE;
        }
        *result = destination;

        return 0;
    }

    // The clock-parameterized waits over musl's CLOCK_REALTIME-based timed
    // calls: the deadline converts through "remaining time", which admits a
    // clock-jump race glibc's native versions do not have.
    static struct timespec convertDeadline(clockid_t clock, const struct timespec* deadline) {
        struct timespec source;
        struct timespec real;

        clock_gettime(clock, &source);
        clock_gettime(CLOCK_REALTIME, &real);

        auto nanoseconds = (deadline->tv_sec - source.tv_sec) * 1000000000ll + (deadline->tv_nsec - source.tv_nsec);
        auto absolute = real.tv_sec * 1000000000ll + real.tv_nsec + (nanoseconds > 0 ? nanoseconds : 0);

        return {absolute / 1000000000ll, absolute % 1000000000ll};
    }

    static int sh_pthread_cond_clockwait(pthread_cond_t* condition, pthread_mutex_t* mutex, clockid_t clock, const struct timespec* deadline) {
        auto real = convertDeadline(clock, deadline);

        return pthread_cond_timedwait(condition, mutex, &real);
    }

    static int sh_pthread_mutex_clocklock(pthread_mutex_t* mutex, clockid_t clock, const struct timespec* deadline) {
        auto real = convertDeadline(clock, deadline);

        return pthread_mutex_timedlock(mutex, &real);
    }

    static int sh_pthread_clockjoin_np(pthread_t thread, void** value, clockid_t clock, const struct timespec* deadline) {
        auto real = convertDeadline(clock, deadline);

        return pthread_timedjoin_np(thread, value, &real);
    }

    static int sh_sem_clockwait(sem_t* semaphore, clockid_t clock, const struct timespec* deadline) {
        auto real = convertDeadline(clock, deadline);

        return sem_timedwait(semaphore, &real);
    }

    static long long sh_isoc23_wcstoll(const wchar_t* text, wchar_t** end, int base) {
        return wcstoll(text, end, base);
    }

    static unsigned long long sh_isoc23_wcstoull(const wchar_t* text, wchar_t** end, int base) {
        return wcstoull(text, end, base);
    }

    static size_t sh_wcslcpy(wchar_t* destination, const wchar_t* source, size_t size) {
        auto length = wcslen(source);

        if (size) {
            auto copied = length < size - 1 ? length : size - 1;

            wmemcpy(destination, source, copied);
            destination[copied] = 0;
        }

        return length;
    }

    static size_t sh_wcslcat(wchar_t* destination, const wchar_t* source, size_t size) {
        auto used = wcsnlen(destination, size);

        if (used == size) {
            return size + wcslen(source);
        }

        return used + sh_wcslcpy(destination + used, source, size - used);
    }

    // Scheduling preferences musl does not model; accepting them changes
    // fairness, never correctness.
    static int sh_pthread_rwlockattr_setkind_np(void* attribute, int kind) {
        (void)attribute;
        if (kind < 0 || kind > 2) {
            return EINVAL;
        }

        return 0;
    }

    static int sh_pthread_attr_setaffinity_np(void* attribute, size_t size, const void* set) {
        (void)attribute;
        (void)size;
        (void)set;

        return 0;
    }

    // The pre-2.34 glibc cleanup ABI: pthread_cleanup_push registered a
    // longjmp buffer for the cancellation unwinder. Without glibc-style
    // cancellation the registration chain is never walked, so registering is
    // a no-op — but reaching the unwinder itself means a cancellation we
    // cannot deliver, and that stays loud.
    static void sh_pthread_register_cancel(void* buffer) {
        (void)buffer;
    }

    static void sh_pthread_unregister_cancel(void* buffer) {
        (void)buffer;
    }

    [[noreturn]] static void sh_pthread_unwind_next(void* buffer) {
        (void)buffer;
        fputs("glibc bridge: __pthread_unwind_next: glibc-style cancellation is not supported\n", stderr);
        abort();
    }

    static void sh_error(int status, int number, const char* format, ...) {
        fflush(stdout);
        fprintf(stderr, "%s: ", program_invocation_short_name);

        va_list arguments;

        va_start(arguments, format);
        vfprintf(stderr, format, arguments);
        va_end(arguments);
        if (number) {
            fprintf(stderr, ": %s", strerror(number));
        }
        fputc('\n', stderr);
        if (status) {
            exit(status);
        }
    }

    // The argz vectors: NUL-separated strings in one malloc'd block.
    static int sh_argz_append(char** argz, size_t* length, const char* extra, size_t extraLength) {
        auto* grown = static_cast<char*>(realloc(*argz, *length + extraLength));

        if (!grown && *length + extraLength) {
            return ENOMEM;
        }
        memcpy(grown + *length, extra, extraLength);
        *argz = grown;
        *length += extraLength;

        return 0;
    }

    static int sh_argz_create_sep(const char* text, int separator, char** argz, size_t* length) {
        *argz = nullptr;
        *length = 0;

        auto size = strlen(text);

        if (!size) {
            return 0;
        }

        auto* block = static_cast<char*>(malloc(size + 1));

        if (!block) {
            return ENOMEM;
        }

        size_t used = 0;
        size_t start = 0;

        for (size_t index = 0; index <= size; ++index) {
            if (text[index] == separator || !text[index]) {
                if (index > start) {
                    memcpy(block + used, text + start, index - start);
                    used += index - start;
                    block[used++] = 0;
                }
                start = index + 1;
            }
        }
        *argz = block;
        *length = used;

        return 0;
    }

    static int sh_argz_insert(char** argz, size_t* length, char* before, const char* entry) {
        auto entryLength = strlen(entry) + 1;

        if (!before) {
            return sh_argz_append(argz, length, entry, entryLength);
        }

        auto offset = before - *argz;
        auto* grown = static_cast<char*>(realloc(*argz, *length + entryLength));

        if (!grown) {
            return ENOMEM;
        }
        memmove(grown + offset + entryLength, grown + offset, *length - offset);
        memcpy(grown + offset, entry, entryLength);
        *argz = grown;
        *length += entryLength;

        return 0;
    }

    static void sh_argz_stringify(char* argz, size_t length, int separator) {
        for (size_t index = 0; index + 1 < length; ++index) {
            if (!argz[index]) {
                argz[index] = (char)separator;
            }
        }
    }

    // argp's error reporting without argp's parser: the program name and the
    // message are what callers rely on.
    static void sh_argp_failure(void* state, int status, int number, const char* format, ...) {
        (void)state;
        fprintf(stderr, "%s: ", program_invocation_short_name);

        va_list arguments;

        va_start(arguments, format);
        vfprintf(stderr, format, arguments);
        va_end(arguments);
        if (number) {
            fprintf(stderr, ": %s", strerror(number));
        }
        fputc('\n', stderr);
        if (status) {
            exit(status);
        }
    }

    [[noreturn]] static void sh_argp_error(void* state, const char* format, ...) {
        (void)state;
        fprintf(stderr, "%s: ", program_invocation_short_name);

        va_list arguments;

        va_start(arguments, format);
        vfprintf(stderr, format, arguments);
        va_end(arguments);
        fputc('\n', stderr);
        exit(64);
    }

    // GNU obstacks, by the book: the struct layout is public ABI, and gmp's
    // formatted output grows through these two entry points.
    struct GlibcObstackChunk {
        char* limit;
        GlibcObstackChunk* previous;
    };

    struct GlibcObstack {
        long chunkSize;
        GlibcObstackChunk* chunk;
        char* objectBase;
        char* nextFree;
        char* chunkLimit;
        union {
            uintptr_t number;
            void* pointer;
        } temporary;
        int alignmentMask;
        void* (*allocate)(void*, long);
        void (*release)(void*, void*);
        void* extraArgument;
        unsigned useExtraArgument : 1;
        unsigned maybeEmptyObject : 1;
        unsigned allocationFailed : 1;
    };

    static void* obstackAllocate(GlibcObstack* obstack, long size) {
        if (obstack->useExtraArgument) {
            return obstack->allocate(obstack->extraArgument, size);
        }

        return reinterpret_cast<void* (*)(long)>(reinterpret_cast<uintptr_t>(obstack->allocate))(size);
    }

    static int sh_obstack_begin(GlibcObstack* obstack, int size, int alignment, void* (*allocate)(long), void (*release)(void*)) {
        if (!alignment) {
            alignment = alignof(max_align_t);
        }
        if (!size) {
            size = 4096;
        }
        obstack->chunkSize = size;
        obstack->alignmentMask = alignment - 1;
        obstack->allocate = reinterpret_cast<void* (*)(void*, long)>(reinterpret_cast<uintptr_t>(allocate));
        obstack->release = reinterpret_cast<void (*)(void*, void*)>(reinterpret_cast<uintptr_t>(release));
        obstack->useExtraArgument = 0;
        obstack->maybeEmptyObject = 0;
        obstack->allocationFailed = 0;

        auto* chunk = static_cast<GlibcObstackChunk*>(obstackAllocate(obstack, size));

        if (!chunk) {
            fputs("glibc bridge: obstack allocation failed\n", stderr);
            abort();
        }
        obstack->chunk = chunk;
        obstack->chunkLimit = chunk->limit = reinterpret_cast<char*>(chunk) + size;
        obstack->objectBase = obstack->nextFree = reinterpret_cast<char*>(chunk + 1);
        chunk->previous = nullptr;

        return 1;
    }

    static void sh_obstack_newchunk(GlibcObstack* obstack, int length) {
        auto objectSize = obstack->nextFree - obstack->objectBase;
        auto needed = objectSize + length + (objectSize >> 3) + obstack->alignmentMask + 100;
        auto size = needed > obstack->chunkSize ? needed : obstack->chunkSize;
        auto* fresh = static_cast<GlibcObstackChunk*>(obstackAllocate(obstack, size + (long)sizeof(GlibcObstackChunk)));

        if (!fresh) {
            fputs("glibc bridge: obstack allocation failed\n", stderr);
            abort();
        }
        fresh->previous = obstack->chunk;
        fresh->limit = reinterpret_cast<char*>(fresh) + size + sizeof(GlibcObstackChunk);

        auto* base = reinterpret_cast<char*>(fresh + 1);

        base += (reinterpret_cast<uintptr_t>(base) + obstack->alignmentMask & ~(uintptr_t)obstack->alignmentMask) - reinterpret_cast<uintptr_t>(base);
        memcpy(base, obstack->objectBase, objectSize);
        obstack->chunk = fresh;
        obstack->chunkLimit = fresh->limit;
        obstack->objectBase = base;
        obstack->nextFree = base + objectSize;
    }

    static int sh_obstack_vprintf(GlibcObstack* obstack, const char* format, va_list arguments) {
        char* text = nullptr;
        auto length = vasprintf(&text, format, arguments);

        if (length < 0) {
            return -1;
        }
        if (obstack->nextFree + length > obstack->chunkLimit) {
            sh_obstack_newchunk(obstack, length);
        }
        memcpy(obstack->nextFree, text, length);
        obstack->nextFree += length;
        free(text);

        return length;
    }

    // The fortified spellings glibc's obstack.h emits under _FORTIFY_SOURCE;
    // the flag only selects the checking mode, the growth is the same.
    static int sh_obstack_vprintf_chk(GlibcObstack* obstack, int flag, const char* format, va_list arguments) {
        (void)flag;

        return sh_obstack_vprintf(obstack, format, arguments);
    }

    static int sh_obstack_printf_chk(GlibcObstack* obstack, int flag, const char* format, ...) {
        (void)flag;

        va_list arguments;
        va_start(arguments, format);
        auto length = sh_obstack_vprintf(obstack, format, arguments);
        va_end(arguments);

        return length;
    }

    // A well-formed, honestly empty malloc_info document.
    static int sh_malloc_info(int options, FILE* stream) {
        (void)options;
        fputs("<malloc version=\"1\"></malloc>\n", stream);

        return 0;
    }

    static const char* sh_strerrordesc_np(int number) {
        return strerror(number);
    }

    // Without NSS there are no netgroups: nothing is ever a member.
    static int sh_innetgr(const char* group, const char* host, const char* user, const char* domain) {
        (void)group;
        (void)host;
        (void)user;
        (void)domain;

        return 0;
    }

    // glibc's utmp and utmpx are the same 384-byte record on both supported
    // architectures.
    static void sh_getutmpx(const void* utmp, void* utmpx) {
        memcpy(utmpx, utmp, 384);
    }

    static void sh_getutmp(const void* utmpx, void* utmp) {
        memcpy(utmp, utmpx, 384);
    }

    static unsigned sh_gnu_dev_major(unsigned long long device) {
        return ((device >> 31 >> 1) & 0xfffff000) | ((device >> 8) & 0xfff);
    }

    static unsigned sh_gnu_dev_minor(unsigned long long device) {
        return ((device >> 12) & 0xffffff00) | (device & 0xff);
    }

    static uint32_t sh_arc4random_uniform(uint32_t bound) {
        if (bound < 2) {
            return 0;
        }

        // Rejection sampling over getrandom keeps the distribution exact.
        auto limit = -bound % bound;

        for (;;) {
            uint32_t value;

            if (getrandom(&value, sizeof(value), 0) != sizeof(value)) {
                continue;
            }
            if (value >= limit) {
                return value % bound;
            }
        }
    }

    // The printf-hook registry has no musl counterpart, and the API allows
    // registration to fail; callers (libquadmath's constructor) must cope.
    static int sh_register_printf_failure(void) {
        errno = ENOSYS;

        return -1;
    }

    // The high end of the initial thread's stack, like ld.so publishes it;
    // conservative stack scanners read this. Filled at adapter startup from
    // the maps.
    static void* sh_libc_stack_end = nullptr;

    // The gettext catalog change counter; nothing invalidates.
    static int sh_nl_msg_cat_cntr = 0;

    static void* findStackEnd() {
        auto* maps = fopen("/proc/self/maps", "r");
        char line[256];
        unsigned long end = 0;

        while (maps && fgets(line, sizeof(line), maps)) {
            unsigned long low = 0;
            unsigned long high = 0;

            if (strstr(line, "[stack]") && sscanf(line, "%lx-%lx", &low, &high) == 2) {
                end = high;
                break;
            }
        }
        if (maps) {
            fclose(maps);
        }

        return reinterpret_cast<void*>(end);
    }

    // makecontext against the same glibc ucontext_t the assembly reads: the
    // caller has already run getcontext on it, per the contract, so only the
    // stack, the entry point, the register arguments, and the trampoline's
    // successor pointer are written here.
    static void sh_makecontext(void* context, void (*function)(), int argc, ...) {
        auto* bytes = static_cast<char*>(context);
        auto* link = *reinterpret_cast<void**>(bytes + 8);
        auto* stackBase = *reinterpret_cast<char**>(bytes + 16);
        auto stackSize = *reinterpret_cast<size_t*>(bytes + 32);
        auto top = (reinterpret_cast<uintptr_t>(stackBase) + stackSize) & ~uintptr_t(15);

        uint64_t arguments[8] = {};
        va_list list;

        va_start(list, argc);
        for (int index = 0; index < argc && index < 8; ++index) {
            arguments[index] = va_arg(list, long);
        }
        va_end(list);

#if defined(__x86_64__)
        auto* gregs = reinterpret_cast<uint64_t*>(bytes + 40);

        // The synthetic call frame: at entry the return slot holds the
        // trampoline, and %rsp is 8 mod 16, like after a real call.
        top -= 8;
        *reinterpret_cast<uint64_t*>(top) = reinterpret_cast<uint64_t>(soloStartContext);
        gregs[16] = reinterpret_cast<uint64_t>(function);
        gregs[15] = top;
        gregs[11] = reinterpret_cast<uint64_t>(link);
        gregs[8] = arguments[0];
        gregs[9] = arguments[1];
        gregs[12] = arguments[2];
        gregs[14] = arguments[3];
        gregs[0] = arguments[4];
        gregs[1] = arguments[5];
#elif defined(__aarch64__)
        auto* registers = reinterpret_cast<uint64_t*>(bytes + 184);

        for (int index = 0; index < 8; ++index) {
            registers[index] = arguments[index];
        }
        registers[19] = reinterpret_cast<uint64_t>(link);
        registers[30] = reinterpret_cast<uint64_t>(soloStartContext);
        *reinterpret_cast<uint64_t*>(bytes + 440) = reinterpret_cast<uint64_t>(function);
        *reinterpret_cast<uint64_t*>(bytes + 432) = top;
#endif
    }

    // The version of the glibc whose inventory the bridge was generated
    // from; sanitizer runtimes gate feature probes on it.
    static const char* sh_gnu_get_libc_version(void) {
#if defined(__x86_64__)
        return "2.44";
#elif defined(__aarch64__)
        return "2.42";
#endif
    }

    // The allocation half of glibc's CPU_ALLOC/CPU_FREE macros: a bitmask of
    // count CPUs in 64-bit words.
    static void* sh_sched_cpualloc(size_t count) {
        return malloc((count + 63) / 64 * 8);
    }

    static void sh_sched_cpufree(void* set) {
        free(set);
    }

    // glibc reads /etc/ttys, which Linux systems do not ship, so every
    // lookup fails; a machine that actually has the file deserves a loud
    // stop instead of invented entries.
    static void* sh_getttynam(const char* name) {
        (void)name;
        if (access("/etc/ttys", F_OK) == 0) {
            fputs("glibc bridge: getttynam: /etc/ttys exists but is not supported\n", stderr);
            abort();
        }

        return nullptr;
    }

    static int sh_creat64(const char* path, mode_t mode) {
        return creat(path, mode);
    }

    static int sh_fallocate64(int descriptor, int mode, off_t offset, off_t size) {
        return fallocate(descriptor, mode, offset, size);
    }

    static FILE* sh_freopen64(const char* path, const char* mode, FILE* stream) {
        return freopen(path, mode, stream);
    }

    static int sh_statvfs64(const char* path, struct statvfs* status) {
        return statvfs(path, status);
    }

    static int sh_fstatvfs64(int descriptor, struct statvfs* status) {
        return fstatvfs(descriptor, status);
    }

    static int sh_getrlimit64(int resource, struct rlimit* limit) {
        return getrlimit(resource, limit);
    }

    static int sh_setrlimit64(int resource, const struct rlimit* limit) {
        return setrlimit(resource, limit);
    }

    static int sh_posix_fadvise64(int descriptor, off_t offset, off_t size, int advice) {
        return posix_fadvise(descriptor, offset, size, advice);
    }

    static int sh_versionsort64(const struct dirent** left, const struct dirent** right) {
        return versionsort(left, right);
    }

    static int sh_scandirat64(int directory, const char* path, struct dirent*** entries, int (*filter)(const struct dirent*), int (*compare)(const struct dirent**, const struct dirent**)) {
        if (!path || path[0] == '/' || directory == AT_FDCWD) {
            return scandir(path, entries, filter, compare);
        }

        char resolved[PATH_MAX];

        snprintf(resolved, sizeof(resolved), "/proc/self/fd/%d/%s", directory, path);
        return scandir(resolved, entries, filter, compare);
    }

    static int sh_malloc_trim(size_t pad) {
        (void)pad;
        return 0;
    }

    struct ShMallinfo2 {
        size_t values[10];
    };

    static ShMallinfo2 sh_mallinfo2(void) {
        return {};
    }

    static const char* sh_strerrorname_np(int error) {
        (void)error;
        return nullptr;
    }

    static int sh_rpmatch(const char* response) {
        if (response && (*response == 'y' || *response == 'Y')) {
            return 1;
        }
        if (response && (*response == 'n' || *response == 'N')) {
            return 0;
        }
        return -1;
    }

    static int sh_getsgnam_r(const char* name, void* record, char* buffer, size_t size, void** result) {
        (void)name;
        (void)record;
        (void)buffer;
        (void)size;
        if (result) {
            *result = nullptr;
        }
        return 0;
    }

    // The res_n* API over musl's stateless resolver: the glibc res_state is
    // opaque to us and stays untouched.
    static int sh_res_ninit(void* state) {
        (void)state;
        return 0;
    }

    static void sh_res_nclose(void* state) {
        (void)state;
    }

    static int sh_res_nquery(void* state, const char* name, int record_class, int type, unsigned char* answer, int length) {
        (void)state;
        return res_query(name, record_class, type, answer, length);
    }

    static int sh_res_nsearch(void* state, const char* name, int record_class, int type, unsigned char* answer, int length) {
        (void)state;
        return res_search(name, record_class, type, answer, length);
    }

    static int sh_res_nsend(void* state, const unsigned char* message, int messageLength, unsigned char* answer, int length) {
        (void)state;
        return res_send(message, messageLength, answer, length);
    }

    static int sh_res_nmkquery(void* state, int operation, const char* name, int record_class, int type, const unsigned char* data, int dataLength, const unsigned char* record, unsigned char* buffer, int length) {
        (void)state;
        return res_mkquery(operation, name, record_class, type, data, dataLength, record, buffer, length);
    }

    // The gshadow records musl has no reader for: parse and print the
    // colon-separated line format directly.
    static struct {
        char line[512];
        char* administrators[33];
        char* members[33];
        void* record[4];
    } sgentState;

    static char** splitList(char* text, char** list, size_t limit) {
        size_t count = 0;

        while (text && *text && count < limit - 1) {
            list[count++] = text;

            auto* comma = strchr(text, ',');

            if (comma) {
                *comma = 0;
            }
            text = comma ? comma + 1 : nullptr;
        }
        list[count] = nullptr;

        return list;
    }

    static void* sh_fgetsgent(FILE* stream) {
        if (!stream || !fgets(sgentState.line, sizeof(sgentState.line), stream)) {
            return nullptr;
        }
        sgentState.line[strcspn(sgentState.line, "\n")] = 0;

        char* fields[4] = {};
        char* cursor = sgentState.line;

        for (int index = 0; index < 4 && cursor; ++index) {
            fields[index] = cursor;

            auto* colon = strchr(cursor, ':');

            if (colon) {
                *colon = 0;
            }
            cursor = colon ? colon + 1 : nullptr;
        }
        if (!fields[3]) {
            return nullptr;
        }
        sgentState.record[0] = fields[0];
        sgentState.record[1] = fields[1];
        sgentState.record[2] = splitList(fields[2], sgentState.administrators, 33);
        sgentState.record[3] = splitList(fields[3], sgentState.members, 33);

        return sgentState.record;
    }

    static int sh_putsgent(const void* record, FILE* stream) {
        auto* fields = static_cast<void* const*>(record);
        auto* name = static_cast<const char*>(fields[0]);
        auto* password = static_cast<const char*>(fields[1]);

        if (fprintf(stream, "%s:%s:", name ? name : "", password ? password : "") < 0) {
            return -1;
        }
        for (int field = 2; field < 4; ++field) {
            auto* list = static_cast<char* const*>(fields[field]);

            for (int index = 0; list && list[index]; ++index) {
                if (fprintf(stream, "%s%s", index ? "," : "", list[index]) < 0) {
                    return -1;
                }
            }
            if (fputc(field == 2 ? ':' : '\n', stream) == EOF) {
                return -1;
            }
        }

        return 0;
    }

    static size_t sh_parse_printf_format(const char* format, size_t count, int* types) {
        enum {
            PaInt,
            PaChar,
            PaWchar,
            PaString,
            PaWstring,
            PaPointer,
            PaFloat,
            PaDouble,
            PaFlagLongLong = 0x100,
            PaFlagLong = 0x200,
            PaFlagShort = 0x400,
            PaFlagPtr = 0x800,
        };
        size_t used = 0;
        auto emit = [&](int type) {
            if (used < count) {
                types[used] = type;
            }
            ++used;
        };

        for (const char* cursor = format; *cursor; ++cursor) {
            if (*cursor != '%') {
                continue;
            }
            ++cursor;
            if (*cursor == '%') {
                continue;
            }
            while (*cursor == '-' || *cursor == '+' || *cursor == ' ' || *cursor == '#' || *cursor == '0' || *cursor == '\'' || *cursor == 'I') {
                ++cursor;
            }
            if (*cursor == '*') {
                emit(PaInt);
                ++cursor;
            } else {
                while (isdigit((unsigned char)*cursor)) {
                    ++cursor;
                }
            }
            if (*cursor == '.') {
                ++cursor;
                if (*cursor == '*') {
                    emit(PaInt);
                    ++cursor;
                } else {
                    while (isdigit((unsigned char)*cursor)) {
                        ++cursor;
                    }
                }
            }
            int flags = 0;
            for (;;) {
                if (*cursor == 'h') {
                    flags = PaFlagShort;
                    ++cursor;
                    if (*cursor == 'h') {
                        ++cursor;
                    }
                } else if (*cursor == 'l') {
                    flags = PaFlagLong;
                    ++cursor;
                    if (*cursor == 'l') {
                        flags = PaFlagLongLong;
                        ++cursor;
                    }
                } else if (*cursor == 'j' || *cursor == 'z' || *cursor == 't' || *cursor == 'q' || *cursor == 'L') {
                    flags = PaFlagLongLong;
                    ++cursor;
                } else {
                    break;
                }
            }
            if (!*cursor) {
                break;
            }
            switch (*cursor) {
                case 'd':
                case 'i':
                case 'u':
                case 'o':
                case 'x':
                case 'X':
                    emit(PaInt | flags);
                    break;
                case 'c':
                    emit(flags & PaFlagLong ? PaWchar : PaChar);
                    break;
                case 's':
                    emit(flags & PaFlagLong ? PaWstring : PaString);
                    break;
                case 'p':
                    emit(PaPointer);
                    break;
                case 'f':
                case 'F':
                case 'e':
                case 'E':
                case 'g':
                case 'G':
                case 'a':
                case 'A':
                    emit(PaDouble | flags);
                    break;
                case 'n':
                    emit(PaInt | PaFlagPtr);
                    break;
                default:
                    break;
            }
        }

        return used;
    }

    // glibc regmatch_t holds int offsets while musl's are 64-bit
    // (dev/abi-diff.txt), so the regex family cannot pass through: the musl
    // object lives behind the buffer field of the caller's glibc regex_t, and
    // matches are converted.
    struct GlibcRegex {
        regex_t* shadow;
        unsigned long reserved[5];
        size_t re_nsub;
        unsigned long flags;
    };

    struct GlibcRegmatch {
        int rm_so;
        int rm_eo;
    };

    static_assert(sizeof(GlibcRegex) == sizeof(regex_t));

    static int sh_regcomp(GlibcRegex* compiled, const char* pattern, int cflags) {
        auto* shadow = static_cast<regex_t*>(calloc(1, sizeof(regex_t)));

        if (!shadow) {
            return REG_ESPACE;
        }
        if (int result = regcomp(shadow, pattern, cflags)) {
            free(shadow);
            return result;
        }

        compiled->shadow = shadow;
        compiled->re_nsub = shadow->re_nsub;
        return 0;
    }

    static int sh_regexec(const GlibcRegex* compiled, const char* string, size_t nmatch, GlibcRegmatch* pmatch, int eflags) {
        regmatch_t buffer[16];
        regmatch_t* matches = buffer;

        if (nmatch > 16) {
            matches = static_cast<regmatch_t*>(calloc(nmatch, sizeof(regmatch_t)));
            if (!matches) {
                return REG_ESPACE;
            }
        }

        int result = regexec(compiled->shadow, string, nmatch, matches, eflags);

        if (result == 0) {
            for (size_t index = 0; index < nmatch; ++index) {
                pmatch[index] = {(int)matches[index].rm_so, (int)matches[index].rm_eo};
            }
        }
        if (matches != buffer) {
            free(matches);
        }
        return result;
    }

    static size_t sh_regerror(int code, const GlibcRegex* compiled, char* buffer, size_t size) {
        return regerror(code, compiled && compiled->shadow ? compiled->shadow : nullptr, buffer, size);
    }

    static void sh_regfree(GlibcRegex* compiled) {
        if (compiled && compiled->shadow) {
            regfree(compiled->shadow);
            free(compiled->shadow);
            compiled->shadow = nullptr;
        }
    }

    // The BSD re_* layer over the same shadow: glibc's re_pattern_buffer is
    // its regex_t. Extended syntax is the pragmatic default; re_match is
    // anchored, and leftmost-longest regexec answers anchoring exactly.
    static const char* sh_re_compile_pattern(const char* pattern, size_t length, GlibcRegex* compiled) {
        auto* copy = static_cast<char*>(malloc(length + 1));

        if (!copy) {
            return "out of memory";
        }
        memcpy(copy, pattern, length);
        copy[length] = 0;

        auto result = sh_regcomp(compiled, copy, REG_EXTENDED);

        free(copy);

        return result ? "invalid regular expression" : nullptr;
    }

    struct GlibcReRegisters {
        unsigned count;
        int* start;
        int* end;
    };

    static int sh_re_match(GlibcRegex* compiled, const char* string, int size, int start, GlibcReRegisters* registers) {
        if (!compiled || !compiled->shadow || start < 0 || start > size) {
            return -2;
        }

        auto* copy = static_cast<char*>(malloc(size - start + 1));

        if (!copy) {
            return -2;
        }
        memcpy(copy, string + start, size - start);
        copy[size - start] = 0;

        regmatch_t matches[16] = {};
        auto groups = compiled->re_nsub + 1 < 16 ? compiled->re_nsub + 1 : 16;
        auto result = regexec(compiled->shadow, copy, groups, matches, 0);

        free(copy);
        if (result || matches[0].rm_so != 0) {
            return -1;
        }
        if (registers && registers->count) {
            for (unsigned index = 0; index < registers->count && index < groups; ++index) {
                registers->start[index] = matches[index].rm_so < 0 ? -1 : (int)matches[index].rm_so + start;
                registers->end[index] = matches[index].rm_eo < 0 ? -1 : (int)matches[index].rm_eo + start;
            }
        }

        return matches[0].rm_eo;
    }

    // musl's FTW_* type codes are glibc's plus one (dev/abi-diff.txt), so the
    // callback sees translated codes; the flags match.
    using NftwCallback = int (*)(const char*, const struct stat*, int, struct FTW*);

    static thread_local NftwCallback nftwUserCallback;

    static int sh_nftw_trampoline(const char* path, const struct stat* status, int type, struct FTW* info) {
        return nftwUserCallback(path, status, type - 1, info);
    }

    static int sh_nftw(const char* path, NftwCallback callback, int descriptors, int flags) {
        auto* previous = nftwUserCallback;

        nftwUserCallback = callback;
        int result = nftw(path, sh_nftw_trampoline, descriptors, flags);
        nftwUserCallback = previous;
        return result;
    }

    // C23 sized deallocation: the sizes are advisory.
    static void sh_free_sized(void* pointer, size_t size) {
        (void)size;
        free(pointer);
    }

    static void sh_free_aligned_sized(void* pointer, size_t alignment, size_t size) {
        (void)alignment;
        (void)size;
        free(pointer);
    }

    __attribute__((noreturn)) static void sh_stack_chk_fail(void) {
        abort();
    }

    static void sh_cxa_finalize(void* handle) {
        (void)handle;
    }

    static int sh_cxa_atexit(void (*function)(void*), void* argument, void* dso) {
        return __cxa_atexit(function, argument, dso);
    }

    struct GlibcSymbolKey {
        std::string_view name;
        std::string_view version;

        bool operator==(const GlibcSymbolKey&) const noexcept;
    };

    struct GlibcSymbolKeyHash {
        size_t operator()(const GlibcSymbolKey& key) const noexcept;
    };

    struct GlibcProviders {
        std::unordered_map<GlibcSymbolKey, void*, GlibcSymbolKeyHash> byVersion;
        std::unordered_map<std::string_view, void*> byName;
    };

    struct GlibcHandle;

    struct GlibcAdapter {
        GlibcAdapter();

        static GlibcAdapter& instance();

        const int** ctypeTolower();
        const int** ctypeToupper();
        const unsigned short** ctypeFlags();
        void* libcSingleThreaded();

        bool hasSymbolVersion(std::string_view name, std::string_view version) const;
        void* findOverride(std::string_view name, std::string_view version) const;
        void* findFallback(std::string_view name, std::string_view version) const;
        void* resolveSymbol(std::string_view name, std::string_view version, bool weak);

        GlibcHandle* handleFor(void* stubHandle, bool runtime);
        GlibcHandle* defaultHandle();

        unsigned char libcSingleThreaded_;
        int tolowerTable_[384];
        const int* tolowerPointer_;
        int toupperTable_[384];
        const int* toupperPointer_;
        unsigned short ctypeTable_[384];
        const unsigned short* ctypePointer_;

        GlibcProviders providers_;
        std::unordered_set<std::string_view> overrideNames_;
        std::mutex handleMutex_;
        std::unordered_map<void*, GlibcHandle*> handles_;
        GlibcHandle* lastHandle_ = nullptr;
    };

    static const int** sh_ctype_tolower_loc(void) {
        return GlibcAdapter::instance().ctypeTolower();
    }

    static const int** sh_ctype_toupper_loc(void) {
        return GlibcAdapter::instance().ctypeToupper();
    }

    static const unsigned short** sh_ctype_b_loc(void) {
        return GlibcAdapter::instance().ctypeFlags();
    }

    static size_t sh_ctype_get_mb_cur_max(void) {
        return MB_CUR_MAX;
    }

    static size_t sh_wcrtomb_chk(char* destination, wchar_t character, mbstate_t* state, size_t destinationSize) {
        char encoded[MB_LEN_MAX];
        const size_t size = wcrtomb(encoded, character, state);
        if (size != static_cast<size_t>(-1)) {
            if (size > destinationSize) {
                sh_fortify_fail();
            }
            if (destination != nullptr) {
                memcpy(destination, encoded, size);
            }
        }
        return size;
    }

    [[noreturn]] static void sh_assert_fail(const char* assertion, const char* file, unsigned line, const char* function) {
        fprintf(stderr, "%s:%u: %s: assertion `%s' failed\n", file, line, function, assertion);
        abort();
    }

    static int sh_sched_cpucount(size_t size, const cpu_set_t* set) {
        const auto* bytes = reinterpret_cast<const unsigned char*>(set);
        int result = 0;
        for (size_t index = 0; index < size; ++index) {
            result += __builtin_popcount(bytes[index]);
        }
        return result;
    }

    static char* sh_xpg_basename(char* path) {
        return basename(path);
    }

    static void* sh_rawmemchr(const void* memory, int character) {
        const auto* cursor = static_cast<const unsigned char*>(memory);
        const unsigned char wanted = static_cast<unsigned char>(character);
        while (*cursor != wanted) {
            ++cursor;
        }
        return const_cast<unsigned char*>(cursor);
    }

    static const void* sh_memrchr(const void* memory, int character, size_t size) {
        return memrchr(memory, character, size);
    }

    static const char* sh_strchrnul(const char* string, int character) {
        return strchrnul(string, character);
    }

    static const char* sh_strchr(const char* string, int character) {
        return strchr(string, character);
    }

    static const char* sh_strrchr(const char* string, int character) {
        return strrchr(string, character);
    }

    static const char* sh_strstr(const char* haystack, const char* needle) {
        return strstr(haystack, needle);
    }

    static int sh_register_atfork(void (*prepare)(), void (*parent)(), void (*child)(), void* dso) {
        static_cast<void>(dso);
        return pthread_atfork(prepare, parent, child);
    }

    static void sh_syslog_chk(int priority, int flag, const char* format, ...) {
        static_cast<void>(flag);
        va_list arguments;
        va_start(arguments, format);
        vsyslog(priority, format, arguments);
        va_end(arguments);
    }

    struct ShDlIterateContext: public ElfProgramHeaderCallback {
        ShDlIterateContext(int (*callback)(dl_phdr_info*, size_t, void*), void* data);

        int call(const ElfProgramHeaders& image) override;

        int (*callback)(dl_phdr_info*, size_t, void*);
        void* data;
    };

    struct GlibcDlFindObject {
        uint64_t flags;
        void* mapStart;
        void* mapEnd;
        void* linkMap;
        void* ehFrame;
        void* sframe;
        uint64_t reserved[6];
    };

    static_assert(sizeof(GlibcDlFindObject) == 96);

    struct ShDlFindObjectContext: public ElfProgramHeaderCallback {
        ShDlFindObjectContext(const void* address, GlibcDlFindObject* result);

        int call(const ElfProgramHeaders& image) override;

        uintptr_t address;
        GlibcDlFindObject* result;
        bool found;
    };
}

ShDlIterateContext::ShDlIterateContext(int (*callback)(dl_phdr_info*, size_t, void*), void* data)
    : callback(callback)
    , data(data)
{
}

int ShDlIterateContext::call(const ElfProgramHeaders& image) {
    dl_phdr_info info{};
    info.dlpi_addr = image.base;
    info.dlpi_name = image.path;
    info.dlpi_phdr = image.headers;
    info.dlpi_phnum = image.count;
    info.dlpi_tls_modid = image.tlsModule;
    info.dlpi_tls_data = image.tlsData;

    return callback(&info, sizeof(info), data);
}

ShDlFindObjectContext::ShDlFindObjectContext(const void* address, GlibcDlFindObject* result)
    : address(reinterpret_cast<uintptr_t>(address))
    , result(result)
    , found(false)
{
}

int ShDlFindObjectContext::call(const ElfProgramHeaders& image) {
    uintptr_t mapStart = UINTPTR_MAX;
    uintptr_t mapEnd = 0;
    void* ehFrame = nullptr;

    for (Elf64_Half index = 0; index < image.count; ++index) {
        const auto& header = image.headers[index];

        if (header.p_type == PT_LOAD) {
            mapStart = std::min(mapStart, image.base + header.p_vaddr);
            mapEnd = std::max(mapEnd, image.base + header.p_vaddr + header.p_memsz);
        } else if (header.p_type == PT_GNU_EH_FRAME) {
            ehFrame = reinterpret_cast<void*>(image.base + header.p_vaddr);
        }
    }
    if (address < mapStart || address >= mapEnd) {
        return 0;
    }

    *result = {};
    result->mapStart = reinterpret_cast<void*>(mapStart);
    result->mapEnd = reinterpret_cast<void*>(mapEnd);
    result->ehFrame = ehFrame;
    found = true;
    return 1;
}

namespace {
    static int iterateMainProgramHeaders(int (*callback)(dl_phdr_info*, size_t, void*), void* data) {
        auto* headers = reinterpret_cast<const Elf64_Phdr*>(getauxval(AT_PHDR));
        auto count = static_cast<Elf64_Half>(getauxval(AT_PHNUM));

        if (!headers || !count) {
            return 0;
        }

        uintptr_t base = 0;
        const Elf64_Phdr* tls = nullptr;
        for (Elf64_Half index = 0; index < count; ++index) {
            if (headers[index].p_type == PT_PHDR) {
                base = reinterpret_cast<uintptr_t>(headers) - headers[index].p_vaddr;
            } else if (headers[index].p_type == PT_TLS) {
                tls = &headers[index];
            }
        }

        dl_phdr_info info{};
        info.dlpi_addr = base;
        info.dlpi_name = "/proc/self/exe";
        info.dlpi_phdr = headers;
        info.dlpi_phnum = count;
        info.dlpi_tls_modid = tls ? 1 : 0;
        return callback(&info, sizeof(info), data);
    }

    static int findObjectProgramHeaders(dl_phdr_info* info, size_t size, void* data) {
        static_cast<void>(size);
        auto* context = static_cast<ShDlFindObjectContext*>(data);
        const ElfProgramHeaders image{
            info->dlpi_name,
            info->dlpi_addr,
            info->dlpi_phdr,
            info->dlpi_phnum,
            info->dlpi_tls_modid,
            info->dlpi_tls_data,
        };

        return context->call(image);
    }

    static int shFindObject(void* address, GlibcDlFindObject* result) {
        if (!result) {
            return -1;
        }

        ShDlFindObjectContext context(address, result);
        dl_iterate_phdr(findObjectProgramHeaders, &context);

        return context.found ? 0 : -1;
    }
}

extern "C" int dl_iterate_phdr(int (*callback)(dl_phdr_info*, size_t, void*), void* data) {
    const int hostResult = iterateMainProgramHeaders(callback, data);
    if (hostResult) {
        return hostResult;
    }

    ShDlIterateContext context(callback, data);
    return ElfImage::iterateProgramHeaders(context);
}

// The unwinder linked into the static executable calls _dl_find_object through
// the linker rather than through the bridge table, so this definition stays
// global and interposes the one in the process libc: that is what lets an
// exception unwind through an image SoLo mapped.
extern "C" int _dl_find_object(void* address, GlibcDlFindObject* result) {
    return shFindObject(address, result);
}

namespace {
    static int sh_dl_iterate_phdr(int (*callback)(dl_phdr_info*, size_t, void*), void* data) {
        return dl_iterate_phdr(callback, data);
    }

    // musl sizes its synchronization objects to the glibc ABI of every
    // architecture it supports, so a loaded DSO and the process libc describe
    // the same storage. The bridge therefore works in the caller's object
    // instead of shadowing it: both worlds then see one lock, an object that is
    // never destroyed cannot leak a shadow, and a freed address cannot hand its
    // state to whatever is allocated there next.
    static_assert(sizeof(pthread_t) == 8);
    static_assert(sizeof(pthread_mutex_t) == 40 && alignof(pthread_mutex_t) == 8);
    static_assert(sizeof(pthread_cond_t) == 48 && alignof(pthread_cond_t) == 8);
    static_assert(sizeof(pthread_rwlock_t) == 56 && alignof(pthread_rwlock_t) == 8);
    static_assert(sizeof(pthread_barrier_t) == 32 && alignof(pthread_barrier_t) == 8);
    static_assert(sizeof(pthread_attr_t) == 56 && alignof(pthread_attr_t) == 8);
    static_assert(sizeof(pthread_once_t) == 4 && alignof(pthread_once_t) == 4);
    static_assert(sizeof(pthread_mutexattr_t) == 4);
    static_assert(sizeof(pthread_condattr_t) == 4);

    static constexpr int SH_GLIBC_MUTEX_RECURSIVE = 1;
    static constexpr int SH_GLIBC_MUTEX_ERRORCHECK = 2;

    static int sh_host_mutex_type(int glibcKind) {
        if (glibcKind == SH_GLIBC_MUTEX_RECURSIVE) {
            return PTHREAD_MUTEX_RECURSIVE;
        }
        if (glibcKind == SH_GLIBC_MUTEX_ERRORCHECK) {
            return PTHREAD_MUTEX_ERRORCHECK;
        }

        return PTHREAD_MUTEX_DEFAULT;
    }

    // A statically initialized glibc mutex is all zeroes unless it uses one of
    // the recursive or error-check initializers, which encode __kind at byte
    // offset 16. musl keeps its own type in the first word and never writes
    // that slot, so the kind survives and can be adopted once, on first use.
    static void sh_adopt_static_mutex(void* foreign) {
        auto* words = static_cast<int*>(foreign);
        const int kind = __atomic_load_n(&words[4], __ATOMIC_RELAXED) & 3;

        if (kind != SH_GLIBC_MUTEX_RECURSIVE && kind != SH_GLIBC_MUTEX_ERRORCHECK) {
            return;
        }

        int normal = 0;
        __atomic_compare_exchange_n(&words[0], &normal, kind, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
    }

    static int sh_pthread_mutexattr_init(void* foreign_attributes) {
        *(int*)foreign_attributes = 0;
        return 0;
    }

    static int sh_pthread_mutexattr_settype(void* foreign_attributes, int type) {
        *(int*)foreign_attributes = type;
        return 0;
    }

    static int sh_pthread_mutex_init(void* foreign, const void* foreign_attributes) {
        const int kind = foreign_attributes ? *static_cast<const int*>(foreign_attributes) & 3 : 0;
        pthread_mutexattr_t attributes;
        int result = pthread_mutexattr_init(&attributes);

        if (result == 0 && kind) {
            result = pthread_mutexattr_settype(&attributes, sh_host_mutex_type(kind));
        }
        if (result == 0) {
            result = pthread_mutex_init(static_cast<pthread_mutex_t*>(foreign), &attributes);
        }
        pthread_mutexattr_destroy(&attributes);

        return result;
    }

    static int sh_pthread_mutex_destroy(void* foreign) {
        return pthread_mutex_destroy(static_cast<pthread_mutex_t*>(foreign));
    }

    static int sh_pthread_mutex_lock(void* foreign) {
        sh_adopt_static_mutex(foreign);

        return pthread_mutex_lock(static_cast<pthread_mutex_t*>(foreign));
    }

    static int sh_pthread_mutex_trylock(void* foreign) {
        sh_adopt_static_mutex(foreign);

        return pthread_mutex_trylock(static_cast<pthread_mutex_t*>(foreign));
    }

    static int sh_pthread_mutex_timedlock(void* foreign, const struct timespec* deadline) {
        sh_adopt_static_mutex(foreign);

        return pthread_mutex_timedlock(static_cast<pthread_mutex_t*>(foreign), deadline);
    }

    static int sh_pthread_mutex_unlock(void* foreign) {
        return pthread_mutex_unlock(static_cast<pthread_mutex_t*>(foreign));
    }

    static int sh_pthread_mutexattr_destroy(void* foreign_attributes) {
        (void)foreign_attributes;
        return 0;
    }

    static int sh_trace_enabled(void) {
        return getenv("SH_GLIBC_BRIDGE_TRACE") != NULL;
    }

    static int sh_pthread_once(void* foreign, void (*initialize)(void)) {
        if (sh_trace_enabled()) {
            fprintf(stderr, "glibc bridge: pthread_once(%p, %p)\n", foreign, (void*)(uintptr_t)initialize);
        }

        return pthread_once(static_cast<pthread_once_t*>(foreign), initialize);
    }

    static int sh_pthread_condattr_init(void* foreign_attributes) {
        *(int*)foreign_attributes = CLOCK_REALTIME;
        return 0;
    }

    static int sh_pthread_condattr_setclock(void* foreign_attributes, clockid_t clock) {
        *(int*)foreign_attributes = clock;
        return 0;
    }

    static int sh_pthread_condattr_destroy(void* foreign_attributes) {
        (void)foreign_attributes;
        return 0;
    }

    static int sh_pthread_cond_init(void* foreign, const void* foreign_attributes) {
        pthread_condattr_t attributes;
        bool attributesInitialized = false;
        int result = 0;

        if (foreign_attributes) {
            result = pthread_condattr_init(&attributes);
            attributesInitialized = result == 0;
            if (result == 0) {
                result = pthread_condattr_setclock(&attributes, *static_cast<const int*>(foreign_attributes));
            }
        }
        if (result == 0) {
            result = pthread_cond_init(static_cast<pthread_cond_t*>(foreign), attributesInitialized ? &attributes : nullptr);
        }
        if (attributesInitialized) {
            pthread_condattr_destroy(&attributes);
        }

        return result;
    }

    static int sh_pthread_cond_destroy(void* foreign) {
        return pthread_cond_destroy(static_cast<pthread_cond_t*>(foreign));
    }

    static int sh_pthread_cond_signal(void* foreign) {
        return pthread_cond_signal(static_cast<pthread_cond_t*>(foreign));
    }

    static int sh_pthread_cond_broadcast(void* foreign) {
        return pthread_cond_broadcast(static_cast<pthread_cond_t*>(foreign));
    }

    static int sh_pthread_cond_wait(void* foreign_condition, void* foreign_mutex) {
        sh_adopt_static_mutex(foreign_mutex);

        return pthread_cond_wait(static_cast<pthread_cond_t*>(foreign_condition), static_cast<pthread_mutex_t*>(foreign_mutex));
    }

    static int sh_pthread_cond_timedwait(void* foreign_condition, void* foreign_mutex, const struct timespec* deadline) {
        sh_adopt_static_mutex(foreign_mutex);

        return pthread_cond_timedwait(static_cast<pthread_cond_t*>(foreign_condition), static_cast<pthread_mutex_t*>(foreign_mutex), deadline);
    }

    static int sh_pthread_rwlock_init(void* foreign, const void* attributes) {
        (void)attributes;
        return pthread_rwlock_init(static_cast<pthread_rwlock_t*>(foreign), nullptr);
    }

    static int sh_pthread_rwlock_destroy(void* foreign) {
        return pthread_rwlock_destroy(static_cast<pthread_rwlock_t*>(foreign));
    }

    static int sh_pthread_rwlock_rdlock(void* foreign) {
        return pthread_rwlock_rdlock(static_cast<pthread_rwlock_t*>(foreign));
    }

    static int sh_pthread_rwlock_wrlock(void* foreign) {
        return pthread_rwlock_wrlock(static_cast<pthread_rwlock_t*>(foreign));
    }

    static int sh_pthread_rwlock_unlock(void* foreign) {
        return pthread_rwlock_unlock(static_cast<pthread_rwlock_t*>(foreign));
    }

    static int sh_pthread_barrier_init(void* foreign, const void* attributes, unsigned count) {
        (void)attributes;
        return pthread_barrier_init(static_cast<pthread_barrier_t*>(foreign), nullptr, count);
    }

    static int sh_pthread_barrier_wait(void* foreign) {
        return pthread_barrier_wait(static_cast<pthread_barrier_t*>(foreign));
    }

    static int sh_pthread_barrier_destroy(void* foreign) {
        return pthread_barrier_destroy(static_cast<pthread_barrier_t*>(foreign));
    }

    static int sh_pthread_attr_init(void* foreign) {
        return pthread_attr_init(static_cast<pthread_attr_t*>(foreign));
    }

    static int sh_pthread_attr_destroy(void* foreign) {
        return pthread_attr_destroy(static_cast<pthread_attr_t*>(foreign));
    }

    static int sh_pthread_attr_setstacksize(void* foreign, size_t size) {
        return pthread_attr_setstacksize(static_cast<pthread_attr_t*>(foreign), size);
    }

    // glibc sizes a thread's default stack from the soft RLIMIT_STACK
    // (8 MiB when unlimited); guest code is written against that, and
    // musl's 128 KiB default overflows under it (lttng-ust's listener
    // thread, for one).
    static size_t sh_default_thread_stack(void) {
        rlimit limit;

        if (getrlimit(RLIMIT_STACK, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur >= PTHREAD_STACK_MIN) {
            return limit.rlim_cur;
        }

        return 8 << 20;
    }

    static int sh_pthread_create(uintptr_t* foreign_thread, const void* foreign_attributes, void* (*start)(void*), void* argument) {
        if (sh_trace_enabled()) {
            fprintf(stderr, "glibc bridge: pthread_create(start=%p, argument=%p)\n", (void*)(uintptr_t)start, argument);
        }

        // The guest's attribute object was built through the bridged attr
        // calls, so it is a musl attribute; only a stack size the guest never
        // chose (musl's own default, from the bridged pthread_attr_init) is
        // replaced with the glibc-sized one.
        pthread_attr_t attributes;
        size_t musl_default = 0;
        size_t stack_size = 0;

        pthread_attr_init(&attributes);
        pthread_attr_getstacksize(&attributes, &musl_default);
        if (foreign_attributes) {
            attributes = *static_cast<const pthread_attr_t*>(foreign_attributes);
        }
        pthread_attr_getstacksize(&attributes, &stack_size);
        if (stack_size == musl_default) {
            pthread_attr_setstacksize(&attributes, sh_default_thread_stack());
        }

        pthread_t thread;
        const int result = pthread_create(&thread, &attributes, start, argument);

        if (result == 0) {
            *foreign_thread = (uintptr_t)thread;
        }

        return result;
    }

    static int sh_pthread_join(uintptr_t thread, void** result) {
        return pthread_join((pthread_t)thread, result);
    }

    static int sh_pthread_detach(uintptr_t thread) {
        return pthread_detach((pthread_t)thread);
    }

    static int sh_pthread_cancel(uintptr_t thread) {
        return pthread_cancel((pthread_t)thread);
    }

    static uintptr_t sh_pthread_self(void) {
        return (uintptr_t)pthread_self();
    }

    static int sh_pthread_getname_np(uintptr_t thread, char* name, size_t size) {
        return pthread_getname_np((pthread_t)thread, name, size);
    }

    static int sh_pthread_setname_np(uintptr_t thread, const char* name) {
        return pthread_setname_np((pthread_t)thread, name);
    }

    static int sh_pthread_getaffinity_np(uintptr_t thread, size_t size, cpu_set_t* set) {
        return pthread_getaffinity_np((pthread_t)thread, size, set);
    }

    static int sh_pthread_setaffinity_np(uintptr_t thread, size_t size, const cpu_set_t* set) {
        return pthread_setaffinity_np((pthread_t)thread, size, set);
    }

    static int sh_pthread_setschedparam(uintptr_t thread, int policy, const struct sched_param* parameters) {
        return pthread_setschedparam((pthread_t)thread, policy, parameters);
    }

    // The glibc sched_param is a bare int while musl pads its own to 48 bytes
    // (dev/abi-diff.txt); whenever musl copies the whole struct, go through a
    // local one and move only the priority.
    static int sh_pthread_getschedparam(uintptr_t thread, int* policy, int* priority) {
        struct sched_param parameters = {};
        int result = pthread_getschedparam((pthread_t)thread, policy, &parameters);

        if (result == 0) {
            *priority = parameters.sched_priority;
        }
        return result;
    }

    static int sh_pthread_attr_setschedparam(void* attributes, const int* priority) {
        struct sched_param parameters = {};

        parameters.sched_priority = *priority;
        return pthread_attr_setschedparam(static_cast<pthread_attr_t*>(attributes), &parameters);
    }

    static int sh_pthread_attr_getschedparam(const void* attributes, int* priority) {
        struct sched_param parameters = {};
        int result = pthread_attr_getschedparam(static_cast<const pthread_attr_t*>(attributes), &parameters);

        if (result == 0) {
            *priority = parameters.sched_priority;
        }
        return result;
    }

    static int sh_cxa_thread_atexit_impl(void (*function)(void*), void* argument, void* dso_handle) {
        (void)dso_handle;
        ThreadTls::current()->registerDtor(function, argument);
        return 0;
    }

    static FILE* sh_fopen64(const char* path, const char* mode) {
        return fopen(path, mode);
    }

    static int sh_fseeko64(FILE* stream, off_t offset, int origin) {
        return fseeko(stream, offset, origin);
    }

    static off_t sh_ftello64(FILE* stream) {
        return ftello(stream);
    }

    static int sh_open64(const char* path, int flags, ...) {
        if (flags & (O_CREAT | O_TMPFILE)) {
            va_list arguments;
            va_start(arguments, flags);
            mode_t mode = (mode_t)va_arg(arguments, int);
            va_end(arguments);
            return open(path, flags, mode);
        }
        return open(path, flags);
    }

    static int sh_openat64(int directory, const char* path, int flags, ...) {
        if (flags & (O_CREAT | O_TMPFILE)) {
            va_list arguments;
            va_start(arguments, flags);
            mode_t mode = (mode_t)va_arg(arguments, int);
            va_end(arguments);
            return openat(directory, path, flags, mode);
        }
        return openat(directory, path, flags);
    }

    static int sh_open64_2(const char* path, int flags) {
        return open(path, flags);
    }

    static int sh_openat64_2(int directory, const char* path, int flags) {
        return openat(directory, path, flags);
    }

    static int sh_fcntl64(int descriptor, int command, ...) {
        switch (command) {
            case F_GETFD:
            case F_GETFL:
            case F_GETOWN:
                return fcntl(descriptor, command);
            default: {
                va_list arguments;
                va_start(arguments, command);
                uintptr_t argument = va_arg(arguments, uintptr_t);
                va_end(arguments);
                return fcntl(descriptor, command, argument);
            }
        }
    }

    static int sh_stat64(const char* path, struct stat* status) {
        return stat(path, status);
    }

    static int sh_lstat64(const char* path, struct stat* status) {
        return lstat(path, status);
    }

    static int sh_fstat64(int descriptor, struct stat* status) {
        return fstat(descriptor, status);
    }

    static int sh_fstatat64(int directory, const char* path, struct stat* status, int flags) {
        return fstatat(directory, path, status, flags);
    }

    static int sh_statfs64(const char* path, struct statfs* status) {
        return statfs(path, status);
    }

    static int sh_fstatfs64(int descriptor, struct statfs* status) {
        return fstatfs(descriptor, status);
    }

    static off_t sh_lseek64(int descriptor, off_t offset, int origin) {
        return lseek(descriptor, offset, origin);
    }

    static ssize_t sh_pread64(int descriptor, void* destination, size_t size, off_t offset) {
        return pread(descriptor, destination, size, offset);
    }

    static ssize_t sh_pwrite64(int descriptor, const void* source, size_t size, off_t offset) {
        return pwrite(descriptor, source, size, offset);
    }

    static int sh_ftruncate64(int descriptor, off_t size) {
        return ftruncate(descriptor, size);
    }

    static int sh_posix_fallocate64(int descriptor, off_t offset, off_t size) {
        return posix_fallocate(descriptor, offset, size);
    }

    static void* sh_mmap64(void* address, size_t size, int protection, int flags, int descriptor, off_t offset) {
        return mmap(address, size, protection, flags, descriptor, offset);
    }

    static int sh_mkstemp64(char* path_template) {
        return mkstemp(path_template);
    }

    static int sh_mkostemp64(char* path_template, int flags) {
        return mkostemp(path_template, flags);
    }

    static int sh_mkstemps64(char* path_template, int suffix_length) {
        return mkstemps(path_template, suffix_length);
    }

    static struct dirent* sh_readdir64(DIR* directory) {
        return readdir(directory);
    }

    static int sh_alphasort64(const struct dirent** left, const struct dirent** right) {
        return alphasort(left, right);
    }

    static int sh_scandir64(const char* path, struct dirent*** entries, int (*filter)(const struct dirent*), int (*compare)(const struct dirent**, const struct dirent**)) {
        return scandir(path, entries, filter, compare);
    }

    struct GlibcDlInfo {
        const char* filename;
        void* base;
        const char* symbol_name;
        void* symbol_address;
    };

    // The handle sh_glibc_dlopen returns. Its head matches the public prefix
    // of the glibc link_map, because real code casts the handle and walks
    // these fields; the handles chain in load order.
    struct GlibcHandle {
        uintptr_t l_addr = 0;
        const char* l_name = "";
        const void* l_ld = nullptr;
        GlibcHandle* l_next = nullptr;
        GlibcHandle* l_prev = nullptr;

        void* stubHandle = nullptr;
        // A runtime provider bridges the glibc ABI, so overrides come first;
        // a loaded ELF image serves its own symbols first.
        bool runtime = false;

        void* lookup(std::string_view name, std::string_view version) const;
    };

    static void consumeStubError() noexcept {
        stub_dlerror();
    }

    // Leave a pending error for dlerror(): the one the stubs raised, or the
    // fallback when they raised none.
    static void copyStubError(std::string_view fallback) {
        auto* tls = ThreadTls::current();

        if (auto* error = tls->takeDlError(); error) {
            tls->setDlError(error);
        } else {
            tls->setDlError(fallback);
        }
    }

    static void* lookupStub(void* handle, std::string_view name) {
        std::string symbol(name);

        return stub_dlsym(handle, symbol.c_str());
    }

    static void* lookupLibc(std::string_view name) {
        auto* handle = stub_dlopen("c", RTLD_LOCAL);

        return handle ? lookupStub(handle, name) : nullptr;
    }
}

namespace {
    static uintptr_t mainProgramBase() {
        auto* headers = reinterpret_cast<const Elf64_Phdr*>(getauxval(AT_PHDR));
        auto count = getauxval(AT_PHNUM);

        for (unsigned long index = 0; index < count; ++index) {
            if (headers[index].p_type == PT_PHDR) {
                return reinterpret_cast<uintptr_t>(headers) - headers[index].p_vaddr;
            }
        }

        return 0;
    }
}

GlibcHandle* GlibcAdapter::handleFor(void* stubHandle, bool runtime) {
    std::lock_guard lock(handleMutex_);
    auto& slot = handles_[stubHandle];

    if (!slot) {
        auto* handle = new GlibcHandle();

        handle->stubHandle = stubHandle;
        handle->runtime = runtime;
        // The path view of a loaded image is NUL-terminated and lives as long
        // as the image, which is forever.
        if (auto* image = cast<ElfImage>(static_cast<IfaceHandle*>(stubHandle))) {
            handle->l_addr = image->base();
            handle->l_name = image->path().data();
            handle->l_ld = image->dynamicSection();
        }
        handle->l_prev = lastHandle_;
        if (lastHandle_) {
            lastHandle_->l_next = handle;
        }
        lastHandle_ = handle;
        slot = handle;
    }

    return slot;
}

GlibcHandle* GlibcAdapter::defaultHandle() {
    auto* handle = handleFor(stub_dlopen("", RTLD_LOCAL), true);

    if (!handle->l_name[0]) {
        handle->l_addr = mainProgramBase();
        handle->l_name = "/proc/self/exe";
    }

    return handle;
}

void* GlibcHandle::lookup(std::string_view name, std::string_view version) const {
    auto& adapter = GlibcAdapter::instance();

    if (runtime) {
        if (!version.empty() && !adapter.hasSymbolVersion(name, version)) {
            return nullptr;
        }
        if (auto* address = adapter.findOverride(name, version); address) {
            return address;
        }
    }
    if (!runtime && !version.empty()) {
        // dlvsym over a loaded image wants the exact version, no fallbacks.
        if (auto* image = cast<ElfImage>(static_cast<IfaceHandle*>(stubHandle))) {
            return image->lookupVersion(name, version);
        }
    }
    if (auto* address = lookupStub(stubHandle, name); address) {
        return address;
    }
    consumeStubError();
    if (!runtime) {
        if (auto* address = adapter.findOverride(name, version); address) {
            return address;
        }
    }
    if (auto* address = lookupLibc(name); address) {
        return address;
    }
    consumeStubError();

    return adapter.findFallback(name, version);
}

namespace {
    static const char* baseName(const char* path) noexcept {
        if (auto* slash = strrchr(path, '/'); slash) {
            return slash + 1;
        }

        return path;
    }

    static const char* runtimeProvider(const char* path) noexcept {
        auto* name = baseName(path);

        if (strcmp(name, "libdl.so.2") == 0) {
            return "dl";
        }
        if (strcmp(name, "libc.so.6") == 0 || strcmp(name, "libpthread.so.0") == 0 || strcmp(name, "libm.so.6") == 0 || strcmp(name, "librt.so.1") == 0 || strcmp(name, "ld-linux-x86-64.so.2") == 0) {
            return "c";
        }

        return nullptr;
    }

    static int sh_translate_dlopen_flags(int flags) {
        enum {
            SH_GLIBC_RTLD_LAZY = 0x00001,
            SH_GLIBC_RTLD_NOW = 0x00002,
            SH_GLIBC_RTLD_NOLOAD = 0x00004,
            SH_GLIBC_RTLD_DEEPBIND = 0x00008,
            SH_GLIBC_RTLD_GLOBAL = 0x00100,
            SH_GLIBC_RTLD_NODELETE = 0x01000,
        };

        int translated = 0;
        translated |= flags & SH_GLIBC_RTLD_LAZY ? RTLD_LAZY : 0;
        translated |= flags & SH_GLIBC_RTLD_NOW ? RTLD_NOW : 0;
        translated |= flags & SH_GLIBC_RTLD_GLOBAL ? RTLD_GLOBAL : RTLD_LOCAL;
        translated |= flags & SH_GLIBC_RTLD_NODELETE ? RTLD_NODELETE : 0;
        translated |= flags & SH_GLIBC_RTLD_NOLOAD ? RTLD_NOLOAD : 0;
        translated |= flags & SH_GLIBC_RTLD_DEEPBIND ? RTLD_DEEPBIND : 0;
        return translated;
    }

    static void* sh_glibc_dlopen(const char* path, int flags) {
        ThreadTls::current()->clearDlError();

        try {
            if (!path) {
                return GlibcAdapter::instance().defaultHandle();
            }

            auto* provider = runtimeProvider(path);
            auto* handle = stub_dlopen(provider ? provider : path, sh_translate_dlopen_flags(flags));

            if (!handle) {
                copyStubError("library not found");
                return nullptr;
            }

            return GlibcAdapter::instance().handleFor(handle, provider != nullptr);
        } catch (const std::exception& error) {
            ThreadTls::current()->setDlError(error.what());
        } catch (...) {
            ThreadTls::current()->setDlError("unknown dlopen error");
        }

        return nullptr;
    }

    static int sh_dladdr1(const void* address, Dl_info* information, void** extra, int flags) {
        if (!stub_dladdr(address, information)) {
            return 0;
        }
        // RTLD_DL_LINKMAP: the link_map facade of the containing image.
        if (flags == 2 && extra) {
            auto* handle = stub_dlopen(information->dli_fname, RTLD_NOLOAD | RTLD_LOCAL);

            if (!handle) {
                return 0;
            }
            *extra = GlibcAdapter::instance().handleFor(handle, false);
        }

        return 1;
    }

    static void* sh_glibc_dlsym(void* handle, const char* name) {
        ThreadTls::current()->clearDlError();

        if (!name) {
            ThreadTls::current()->setDlError("symbol name is null");
            return nullptr;
        }

        void* address = nullptr;

        if (handle == (void*)(uintptr_t)-1) {
            // RTLD_NEXT: search the images loaded after the caller's one.
            address = ElfImage::lookupNext(__builtin_return_address(0), name, {});
        } else if (!handle) {
            address = GlibcAdapter::instance().defaultHandle()->lookup(name, {});
        } else {
            address = reinterpret_cast<GlibcHandle*>(handle)->lookup(name, {});
        }
        if (!address) {
            copyStubError("symbol not found");
        } else {
            consumeStubError();
        }

        return address;
    }

    static void* sh_glibc_dlvsym(void* handle, const char* name, const char* version) {
        ThreadTls::current()->clearDlError();

        if (!name || !version) {
            ThreadTls::current()->setDlError("symbol name or version is null");
            return nullptr;
        }

        void* address = nullptr;

        if (handle == (void*)(uintptr_t)-1) {
            address = ElfImage::lookupNext(__builtin_return_address(0), name, version);
        } else if (!handle) {
            address = GlibcAdapter::instance().defaultHandle()->lookup(name, version);
        } else {
            address = reinterpret_cast<GlibcHandle*>(handle)->lookup(name, version);
        }
        if (!address) {
            copyStubError("versioned symbol not found");
        } else {
            consumeStubError();
        }

        return address;
    }

    static int sh_glibc_dlclose(void* handle) {
        ThreadTls::current()->clearDlError();

        if (!handle || handle == (void*)(uintptr_t)-1) {
            ThreadTls::current()->setDlError("invalid handle");
            return -1;
        }

        // Handles are owned by the registry; a load-once runtime keeps them.
        return 0;
    }

    static int sh_glibc_dlinfo(void* handle, int request, void* information) {
        ThreadTls::current()->clearDlError();

        if (!handle || handle == (void*)(uintptr_t)-1) {
            ThreadTls::current()->setDlError("invalid handle");
            return -1;
        }
        // RTLD_DI_LINKMAP: the handle already is the link_map facade.
        if (request == 2) {
            *static_cast<void**>(information) = handle;
            return 0;
        }

        ThreadTls::current()->setDlError("unsupported dlinfo request");
        return -1;
    }

    static locale_t sh_newlocale(int mask, const char* name, locale_t base) {
        return newlocale(mask, name, base);
    }

    static locale_t sh_duplocale(locale_t locale) {
        return duplocale(locale);
    }

    static void sh_freelocale(locale_t locale) {
        freelocale(locale);
    }

    static locale_t sh_uselocale(locale_t locale) {
        return uselocale(locale);
    }

    static char* sh_nl_langinfo_l(nl_item item, locale_t locale) {
        return nl_langinfo_l(item, locale);
    }

    static wctype_t sh_wctype_l(const char* name, locale_t locale) {
        return wctype_l(name, locale);
    }

    static int sh_iswctype_l(wint_t character, wctype_t type, locale_t locale) {
        return iswctype_l(character, type, locale);
    }

    static wint_t sh_towlower_l(wint_t character, locale_t locale) {
        return towlower_l(character, locale);
    }

    static wint_t sh_towupper_l(wint_t character, locale_t locale) {
        return towupper_l(character, locale);
    }

    static wctrans_t sh_wctrans_l(const char* name, locale_t locale) {
        return wctrans_l(name, locale);
    }

    static wint_t sh_towctrans_l(wint_t character, wctrans_t transform, locale_t locale) {
        return towctrans_l(character, transform, locale);
    }

    static int sh_glibc_dladdr(const void* address, GlibcDlInfo* glibc_info) {
        Dl_info info;
        int result = stub_dladdr(address, &info);
        if (result && glibc_info) {
            glibc_info->filename = info.dli_fname;
            glibc_info->base = info.dli_fbase;
            glibc_info->symbol_name = info.dli_sname;
            glibc_info->symbol_address = info.dli_saddr;
        }
        return result;
    }

    static const GlibcSymbol sh_glibc_symbols[] = {
        SH_FUNCTION("bcmp", "GLIBC_2.2.5", sh_bcmp),
        SH_FUNCTION("__getdelim", "GLIBC_2.2.5", getdelim),
        SH_FUNCTION("statfs", "GLIBC_2.2.5", statfs),
        SH_FUNCTION("fstatfs", "GLIBC_2.2.5", fstatfs),
        SH_FUNCTION("sigaction", "GLIBC_2.2.5", sigaction),
        SH_FUNCTION("nl_langinfo", "GLIBC_2.2.5", nl_langinfo),
        SH_FUNCTION("wctob", "GLIBC_2.2.5", wctob),
        SH_FUNCTION("btowc", "GLIBC_2.2.5", btowc),
        SH_FUNCTION("getauxval", "GLIBC_2.16", getauxval),
        // aarch64 libgcc probes the LSE hwcap through the internal alias.
        SH_FUNCTION("__getauxval", "GLIBC_2.16", getauxval),
        SH_FUNCTION("__wcrtomb_chk", "GLIBC_2.4", sh_wcrtomb_chk),
        SH_FUNCTION("__ctype_b_loc", "GLIBC_2.3", sh_ctype_b_loc),
        SH_FUNCTION("__ctype_toupper_loc", "GLIBC_2.3", sh_ctype_toupper_loc),
        SH_FUNCTION("__ctype_get_mb_cur_max", "GLIBC_2.2.5", sh_ctype_get_mb_cur_max),
        SH_FUNCTION("ftello", "GLIBC_2.2.5", ftello),
        SH_FUNCTION("lseek", "GLIBC_2.2.5", lseek),
        SH_FUNCTION("__assert_fail", "GLIBC_2.2.5", sh_assert_fail),
        SH_FUNCTION("endpwent", "GLIBC_2.2.5", endpwent),
        SH_FUNCTION("fdopen", "GLIBC_2.2.5", fdopen),
        SH_FUNCTION("fseeko", "GLIBC_2.2.5", fseeko),
        SH_FUNCTION("qsort_r", "GLIBC_2.8", qsort_r),
        SH_FUNCTION("__strtof_l", "GLIBC_2.2.5", strtof_l),
        SH_FUNCTION("__strtod_l", "GLIBC_2.2.5", strtod_l),
        SH_FUNCTION("__strcoll_l", "GLIBC_2.2.5", strcoll_l),
        SH_FUNCTION("__strftime_l", "GLIBC_2.3", strftime_l),
        SH_FUNCTION("__strxfrm_l", "GLIBC_2.2.5", strxfrm_l),
        SH_FUNCTION("__wcsxfrm_l", "GLIBC_2.2.5", wcsxfrm_l),
        SH_FUNCTION("__wcscoll_l", "GLIBC_2.2.5", wcscoll_l),
        SH_FUNCTION("__wcsftime_l", "GLIBC_2.3", wcsftime_l),
        SH_FUNCTION("tzset", "GLIBC_2.2.5", tzset),
        SH_FUNCTION("localtime_r", "GLIBC_2.2.5", localtime_r),
        SH_FUNCTION("gmtime_r", "GLIBC_2.2.5", gmtime_r),
        SH_FUNCTION("__isoc99_sscanf", "GLIBC_2.7", sscanf),
        SH_FUNCTION("mprotect", "GLIBC_2.2.5", mprotect),
        SH_FUNCTION("_Exit", "GLIBC_2.2.5", _Exit),
        SH_FUNCTION("__sched_cpucount", "GLIBC_2.6", sh_sched_cpucount),
        SH_FUNCTION("__xpg_basename", "GLIBC_2.2.5", sh_xpg_basename),
        SH_FUNCTION("rawmemchr", "GLIBC_2.2.5", sh_rawmemchr),
        SH_FUNCTION("mremap", "GLIBC_2.2.5", mremap),
        SH_FUNCTION("memrchr", "GLIBC_2.2.5", sh_memrchr),
        SH_FUNCTION("__isoc99_fscanf", "GLIBC_2.7", fscanf),
        SH_FUNCTION("reallocarray", "GLIBC_2.26", reallocarray),
        SH_FUNCTION("strchrnul", "GLIBC_2.2.5", sh_strchrnul),
        SH_FUNCTION("stpcpy", "GLIBC_2.2.5", stpcpy),
        SH_FUNCTION("__register_atfork", "GLIBC_2.3.2", sh_register_atfork),
        SH_FUNCTION("malloc_usable_size", "GLIBC_2.2.5", malloc_usable_size),
        SH_FUNCTION("__fsetlocking", "GLIBC_2.2.5", __fsetlocking),
        SH_FUNCTION("statx", "GLIBC_2.28", statx),
        SH_FUNCTION("__syslog_chk", "GLIBC_2.4", sh_syslog_chk),
        SH_FUNCTION("clock_nanosleep", "GLIBC_2.17", clock_nanosleep),
        SH_FUNCTION("dl_iterate_phdr", "GLIBC_2.2.5", sh_dl_iterate_phdr),
        SH_FUNCTION("_dl_find_object", "GLIBC_2.35", _dl_find_object),
        // _Unwind_Context is private to the unwinder that created it, so loaded C++ runtimes must use the host unwinder.
        SH_FUNCTION("_Unwind_DeleteException", "GCC_3.0", _Unwind_DeleteException),
        SH_FUNCTION("_Unwind_GetDataRelBase", "GCC_3.0", _Unwind_GetDataRelBase),
        SH_FUNCTION("_Unwind_GetIPInfo", "GCC_4.2.0", _Unwind_GetIPInfo),
        SH_FUNCTION("_Unwind_GetLanguageSpecificData", "GCC_3.0", _Unwind_GetLanguageSpecificData),
        SH_FUNCTION("_Unwind_GetRegionStart", "GCC_3.0", _Unwind_GetRegionStart),
        SH_FUNCTION("_Unwind_GetTextRelBase", "GCC_3.0", _Unwind_GetTextRelBase),
        SH_FUNCTION("_Unwind_RaiseException", "GCC_3.0", _Unwind_RaiseException),
        SH_FUNCTION("_Unwind_Resume", "GCC_3.0", _Unwind_Resume),
        SH_FUNCTION("_Unwind_Resume_or_Rethrow", "GCC_3.3", _Unwind_Resume_or_Rethrow),
        SH_FUNCTION("_Unwind_SetGR", "GCC_3.0", _Unwind_SetGR),
        SH_FUNCTION("_Unwind_SetIP", "GCC_3.0", _Unwind_SetIP),
        SH_FUNCTION("_setjmp", "GLIBC_2.2.5", _setjmp),
        SH_FUNCTION("__longjmp_chk", "GLIBC_2.11", _longjmp),
        SH_OBJECT("__timezone", "GLIBC_2.2.5", timezone),
        SH_OBJECT("tzname", "GLIBC_2.2.5", tzname),
        SH_OBJECT("environ", "GLIBC_2.2.5", environ),
        SH_OBJECT("program_invocation_name", "GLIBC_2.2.5", program_invocation_name),
        SH_OBJECT("program_invocation_short_name", "GLIBC_2.2.5", program_invocation_short_name),
        SH_FUNCTION("__newlocale", "GLIBC_2.2.5", sh_newlocale),
        SH_FUNCTION("__duplocale", "GLIBC_2.2.5", sh_duplocale),
        SH_FUNCTION("__freelocale", "GLIBC_2.2.5", sh_freelocale),
        SH_FUNCTION("__uselocale", "GLIBC_2.3", sh_uselocale),
        SH_FUNCTION("__nl_langinfo_l", "GLIBC_2.2.5", sh_nl_langinfo_l),
        SH_FUNCTION("newlocale", "GLIBC_2.3", sh_newlocale),
        SH_FUNCTION("duplocale", "GLIBC_2.3", sh_duplocale),
        SH_FUNCTION("freelocale", "GLIBC_2.3", sh_freelocale),
        SH_FUNCTION("uselocale", "GLIBC_2.3", sh_uselocale),
        SH_FUNCTION("nl_langinfo_l", "GLIBC_2.3", sh_nl_langinfo_l),
        SH_FUNCTION("__wctype_l", "GLIBC_2.2.5", sh_wctype_l),
        SH_FUNCTION("__iswctype_l", "GLIBC_2.2.5", sh_iswctype_l),
        SH_FUNCTION("__towlower_l", "GLIBC_2.2.5", sh_towlower_l),
        SH_FUNCTION("__towupper_l", "GLIBC_2.2.5", sh_towupper_l),
        SH_FUNCTION("__wctrans_l", "GLIBC_2.2.5", sh_wctrans_l),
        SH_FUNCTION("__towctrans_l", "GLIBC_2.2.5", sh_towctrans_l),
        SH_FUNCTION("wctype_l", "GLIBC_2.3", sh_wctype_l),
        SH_FUNCTION("iswctype_l", "GLIBC_2.3", sh_iswctype_l),
        SH_FUNCTION("towlower_l", "GLIBC_2.3", sh_towlower_l),
        SH_FUNCTION("towupper_l", "GLIBC_2.3", sh_towupper_l),
        SH_FUNCTION("wctrans_l", "GLIBC_2.3", sh_wctrans_l),
        SH_FUNCTION("towctrans_l", "GLIBC_2.3", sh_towctrans_l),
        SH_FUNCTION("__strcat_chk", "GLIBC_2.3.4", sh_strcat_chk),
        SH_FUNCTION("getenv", "GLIBC_2.2.5", getenv),
        SH_FUNCTION("__isoc23_strtoul", "GLIBC_2.38", sh_isoc23_strtoul),
        SH_FUNCTION("__snprintf_chk", "GLIBC_2.3.4", sh_snprintf_chk),
        SH_FUNCTION("dlerror", "GLIBC_2.34", stub_dlerror),
        SH_FUNCTION("free", "GLIBC_2.2.5", free),
        SH_FUNCTION("free_sized", "GLIBC_2.43", sh_free_sized),
        SH_FUNCTION("free_aligned_sized", "GLIBC_2.43", sh_free_aligned_sized),
        SH_FUNCTION("__fdelt_chk", "GLIBC_2.15", sh_fdelt_chk),
        SH_FUNCTION("__fgets_chk", "GLIBC_2.4", sh_fgets_chk),
        SH_FUNCTION("__getcwd_chk", "GLIBC_2.4", sh_getcwd_chk),
        SH_FUNCTION("__getgroups_chk", "GLIBC_2.4", sh_getgroups_chk),
        SH_FUNCTION("__inet_pton_chk", "GLIBC_2.42", sh_inet_pton_chk),
        SH_FUNCTION("__mempcpy_chk", "GLIBC_2.3.4", sh_mempcpy_chk),
        SH_FUNCTION("__open_2", "GLIBC_2.7", sh_open64_2),
        SH_FUNCTION("__poll_chk", "GLIBC_2.16", sh_poll_chk),
        SH_FUNCTION("__stpcpy_chk", "GLIBC_2.3.4", sh_stpcpy_chk),
        SH_FUNCTION("__vsyslog_chk", "GLIBC_2.4", sh_vsyslog_chk),
        SH_FUNCTION("__mbrlen", "GLIBC_2.2.5", mbrlen),
        SH_FUNCTION("__sysconf", "GLIBC_2.2.5", sysconf),
        SH_FUNCTION("__isoc23_strtoimax", "GLIBC_2.38", sh_isoc23_strtoimax),
        SH_FUNCTION("__isoc23_strtoumax", "GLIBC_2.38", sh_isoc23_strtoumax),
        SH_FUNCTION("__isoc23_strtoll_l", "GLIBC_2.38", sh_isoc23_strtoll_l),
        SH_FUNCTION("__isoc23_strtoull_l", "GLIBC_2.38", sh_isoc23_strtoull_l),
        SH_FUNCTION("__isoc23_vfscanf", "GLIBC_2.38", sh_isoc23_vfscanf),
        SH_FUNCTION("close_range", "GLIBC_2.34", sh_close_range),
        SH_FUNCTION("closefrom", "GLIBC_2.34", sh_closefrom),
        SH_FUNCTION("open_tree", "GLIBC_2.36", sh_open_tree),
        SH_FUNCTION("move_mount", "GLIBC_2.36", sh_move_mount),
        SH_FUNCTION("fsopen", "GLIBC_2.36", sh_fsopen),
        SH_FUNCTION("fsconfig", "GLIBC_2.36", sh_fsconfig),
        SH_FUNCTION("fsmount", "GLIBC_2.36", sh_fsmount),
        SH_FUNCTION("fspick", "GLIBC_2.36", sh_fspick),
        SH_FUNCTION("mount_setattr", "GLIBC_2.36", sh_mount_setattr),
        SH_FUNCTION("pidfd_open", "GLIBC_2.36", sh_pidfd_open),
        SH_FUNCTION("gnu_get_libc_version", "GLIBC_2.2.5", sh_gnu_get_libc_version),
        SH_FUNCTION("getcontext", "GLIBC_2.2.5", soloGetcontext),
        SH_FUNCTION("setcontext", "GLIBC_2.2.5", soloSetcontext),
        SH_FUNCTION("swapcontext", "GLIBC_2.2.5", soloSwapcontext),
        SH_FUNCTION("makecontext", "GLIBC_2.2.5", sh_makecontext),
        SH_FUNCTION("backtrace", "GLIBC_2.2.5", sh_backtrace),
        SH_FUNCTION("backtrace_symbols", "GLIBC_2.2.5", sh_backtrace_symbols),
        SH_FUNCTION("backtrace_symbols_fd", "GLIBC_2.2.5", sh_backtrace_symbols_fd),
        SH_FUNCTION("__dprintf_chk", "GLIBC_2.8", sh_dprintf_chk),
        SH_FUNCTION("__vdprintf_chk", "GLIBC_2.8", sh_vdprintf_chk),
        SH_FUNCTION("__vprintf_chk", "GLIBC_2.3.4", sh_vprintf_chk),
        SH_FUNCTION("__swprintf_chk", "GLIBC_2.4", sh_swprintf_chk),
        SH_FUNCTION("__vswprintf_chk", "GLIBC_2.4", sh_vswprintf_chk),
        SH_FUNCTION("__wctomb_chk", "GLIBC_2.4", sh_wctomb_chk),
        SH_FUNCTION("__readlink_chk", "GLIBC_2.4", sh_readlink_chk),
        SH_FUNCTION("__recv_chk", "GLIBC_2.4", sh_recv_chk),
        SH_FUNCTION("__recvfrom_chk", "GLIBC_2.4", sh_recvfrom_chk),
        SH_FUNCTION("__gethostname_chk", "GLIBC_2.4", sh_gethostname_chk),
        SH_FUNCTION("__inet_ntop_chk", "GLIBC_2.42", sh_inet_ntop_chk),
        SH_FUNCTION("sendfile64", "GLIBC_2.3", sh_sendfile64),
        SH_FUNCTION("renameat2", "GLIBC_2.28", sh_renameat2),
        SH_FUNCTION("prlimit64", "GLIBC_2.13", sh_prlimit64),
        SH_FUNCTION("truncate64", "GLIBC_2.2.5", sh_truncate64),
        SH_FUNCTION("tmpfile64", "GLIBC_2.2.5", sh_tmpfile64),
        SH_FUNCTION("pwritev64", "GLIBC_2.10", sh_pwritev64),
        SH_FUNCTION("readdir64_r", "GLIBC_2.2.5", sh_readdir64_r),
        SH_FUNCTION("getdents64", "GLIBC_2.30", sh_getdents64),
        SH_FUNCTION("canonicalize_file_name", "GLIBC_2.2.5", sh_canonicalize_file_name),
        SH_FUNCTION("pidfd_getpid", "GLIBC_2.39", sh_pidfd_getpid),
        SH_FUNCTION("pidfd_spawnp", "GLIBC_2.39", sh_pidfd_spawnp),
        SH_FUNCTION("pkey_alloc", "GLIBC_2.27", sh_pkey_alloc),
        SH_FUNCTION("pkey_free", "GLIBC_2.27", sh_pkey_free),
        SH_FUNCTION("pkey_mprotect", "GLIBC_2.27", sh_pkey_mprotect),
        SH_FUNCTION("pkey_set", "GLIBC_2.27", sh_pkey_set),
        SH_FUNCTION("pkey_get", "GLIBC_2.27", sh_pkey_get),
        SH_FUNCTION("glob64", "GLIBC_2.27", sh_glob64),
        SH_FUNCTION("globfree64", "GLIBC_2.2.5", sh_globfree64),
        SH_FUNCTION("glob_pattern_p", "GLIBC_2.2.5", sh_glob_pattern_p),
        SH_FUNCTION("isnanf", "GLIBC_2.2.5", sh_isnanf),
        SH_FUNCTION("isinff", "GLIBC_2.2.5", sh_isinff),
        SH_FUNCTION("gamma", "GLIBC_2.2.5", sh_gamma),
        SH_FUNCTION("strtof128", "GLIBC_2.26", sh_strtof128),
        SH_FUNCTION("strfromf128", "GLIBC_2.26", sh_strfromf128),
        SH_FUNCTION("logf128", "GLIBC_2.26", sh_logf128),
        SH_FUNCTION("initstate_r", "GLIBC_2.2.5", sh_initstate_r),
        SH_FUNCTION("random_r", "GLIBC_2.2.5", sh_random_r),
        SH_FUNCTION("srandom_r", "GLIBC_2.2.5", sh_srandom_r),
        SH_FUNCTION("getprotobyname_r", "GLIBC_2.2.5", sh_getprotobyname_r),
        SH_FUNCTION("getprotobynumber_r", "GLIBC_2.2.5", sh_getprotobynumber_r),
        SH_FUNCTION("getprotoent_r", "GLIBC_2.2.5", sh_getprotoent_r),
        SH_FUNCTION("getservent_r", "GLIBC_2.2.5", sh_getservent_r),
        SH_FUNCTION("getnetent_r", "GLIBC_2.2.5", sh_getnetent_r),
        SH_FUNCTION("getnetbyname_r", "GLIBC_2.2.5", sh_getnetbyname_r),
        SH_FUNCTION("getnetbyaddr_r", "GLIBC_2.2.5", sh_getnetbyaddr_r),
        SH_FUNCTION("gethostent_r", "GLIBC_2.2.5", sh_gethostent_r),
        SH_FUNCTION("getpwent_r", "GLIBC_2.2.5", sh_getpwent_r),
        SH_FUNCTION("getgrent_r", "GLIBC_2.2.5", sh_getgrent_r),
        SH_FUNCTION("sem_clockwait", "GLIBC_2.34", sh_sem_clockwait),
        SH_FUNCTION("__isoc23_wcstoll", "GLIBC_2.38", sh_isoc23_wcstoll),
        SH_FUNCTION("__isoc23_wcstoull", "GLIBC_2.38", sh_isoc23_wcstoull),
        SH_FUNCTION("wcslcpy", "GLIBC_2.38", sh_wcslcpy),
        SH_FUNCTION("wcslcat", "GLIBC_2.38", sh_wcslcat),
        SH_FUNCTION("pthread_cond_clockwait", "GLIBC_2.34", sh_pthread_cond_clockwait),
        SH_FUNCTION("pthread_mutex_clocklock", "GLIBC_2.34", sh_pthread_mutex_clocklock),
        SH_FUNCTION("pthread_clockjoin_np", "GLIBC_2.34", sh_pthread_clockjoin_np),
        SH_FUNCTION("pthread_rwlockattr_setkind_np", "GLIBC_2.34", sh_pthread_rwlockattr_setkind_np),
        SH_FUNCTION("pthread_attr_setaffinity_np", "GLIBC_2.32", sh_pthread_attr_setaffinity_np),
        SH_FUNCTION("__pthread_register_cancel", "GLIBC_2.34", sh_pthread_register_cancel),
        SH_FUNCTION("__pthread_unregister_cancel", "GLIBC_2.34", sh_pthread_unregister_cancel),
        SH_FUNCTION("__pthread_unwind_next", "GLIBC_2.34", sh_pthread_unwind_next),
        SH_FUNCTION("error", "GLIBC_2.2.5", sh_error),
        SH_FUNCTION("argz_append", "GLIBC_2.2.5", sh_argz_append),
        SH_FUNCTION("argz_create_sep", "GLIBC_2.2.5", sh_argz_create_sep),
        SH_FUNCTION("argz_insert", "GLIBC_2.2.5", sh_argz_insert),
        SH_FUNCTION("argz_stringify", "GLIBC_2.2.5", sh_argz_stringify),
        SH_FUNCTION("argp_failure", "GLIBC_2.2.5", sh_argp_failure),
        SH_FUNCTION("argp_error", "GLIBC_2.2.5", sh_argp_error),
        SH_FUNCTION("_obstack_begin", "GLIBC_2.2.5", sh_obstack_begin),
        SH_FUNCTION("_obstack_newchunk", "GLIBC_2.2.5", sh_obstack_newchunk),
        SH_FUNCTION("obstack_vprintf", "GLIBC_2.2.5", sh_obstack_vprintf),
        SH_FUNCTION("__obstack_vprintf_chk", "GLIBC_2.8", sh_obstack_vprintf_chk),
        SH_FUNCTION("__obstack_printf_chk", "GLIBC_2.8", sh_obstack_printf_chk),
        SH_FUNCTION("malloc_info", "GLIBC_2.10", sh_malloc_info),
        SH_FUNCTION("strerrordesc_np", "GLIBC_2.32", sh_strerrordesc_np),
        SH_FUNCTION("innetgr", "GLIBC_2.2.5", sh_innetgr),
        SH_FUNCTION("getutmpx", "GLIBC_2.2.5", sh_getutmpx),
        SH_FUNCTION("getutmp", "GLIBC_2.2.5", sh_getutmp),
        SH_FUNCTION("gnu_dev_major", "GLIBC_2.3.3", sh_gnu_dev_major),
        SH_FUNCTION("gnu_dev_minor", "GLIBC_2.3.3", sh_gnu_dev_minor),
        SH_FUNCTION("arc4random_uniform", "GLIBC_2.36", sh_arc4random_uniform),
        SH_FUNCTION("fgetsgent", "GLIBC_2.10", sh_fgetsgent),
        SH_FUNCTION("putsgent", "GLIBC_2.10", sh_putsgent),
        SH_FUNCTION("re_compile_pattern", "GLIBC_2.2.5", sh_re_compile_pattern),
        SH_FUNCTION("re_match", "GLIBC_2.2.5", sh_re_match),
        SH_FUNCTION("res_nsearch", "GLIBC_2.34", sh_res_nsearch),
        SH_FUNCTION("__res_nsearch", "GLIBC_2.2.5", sh_res_nsearch),
        SH_FUNCTION("res_nsend", "GLIBC_2.34", sh_res_nsend),
        SH_FUNCTION("__res_nsend", "GLIBC_2.2.5", sh_res_nsend),
        SH_FUNCTION("res_nmkquery", "GLIBC_2.34", sh_res_nmkquery),
        SH_FUNCTION("__res_nmkquery", "GLIBC_2.2.5", sh_res_nmkquery),
        SH_FUNCTION("__res_init", "GLIBC_2.2.5", res_init),
        SH_FUNCTION("dladdr1", "GLIBC_2.34", sh_dladdr1),
        SH_FUNCTION("dladdr1", "GLIBC_2.3.3", sh_dladdr1),
        SH_OBJECT("__libc_stack_end", "GLIBC_2.2.5", sh_libc_stack_end),
        SH_OBJECT("_nl_msg_cat_cntr", "GLIBC_2.2.5", sh_nl_msg_cat_cntr),
        SH_FUNCTION("register_printf_function", "GLIBC_2.2.5", sh_register_printf_failure),
        SH_FUNCTION("register_printf_specifier", "GLIBC_2.10", sh_register_printf_failure),
        SH_FUNCTION("register_printf_modifier", "GLIBC_2.10", sh_register_printf_failure),
        SH_FUNCTION("register_printf_type", "GLIBC_2.10", sh_register_printf_failure),
        // libmvec under both vector ABI spellings; the platform inventory
        // supplies the right versions for whichever names it knows.
        SH_FUNCTION("_ZGVbN2v_cos", "GLIBC_2.22", sh_vector_cos),
        SH_FUNCTION("_ZGVbN2v_sin", "GLIBC_2.22", sh_vector_sin),
        SH_FUNCTION("_ZGVbN2v_log", "GLIBC_2.22", sh_vector_log),
        SH_FUNCTION("_ZGVbN2v_log2", "GLIBC_2.35", sh_vector_log2),
        SH_FUNCTION("_ZGVbN4v_cosf", "GLIBC_2.22", sh_vector_cosf),
        SH_FUNCTION("_ZGVbN4v_sinf", "GLIBC_2.22", sh_vector_sinf),
        SH_FUNCTION("_ZGVbN4v_acosf", "GLIBC_2.35", sh_vector_acosf),
        SH_FUNCTION("_ZGVbN4v_logf", "GLIBC_2.22", sh_vector_logf),
        SH_FUNCTION("_ZGVbN4v_expf", "GLIBC_2.22", sh_vector_expf),
        SH_FUNCTION("_ZGVnN2v_cos", "GLIBC_2.22", sh_vector_cos),
        SH_FUNCTION("_ZGVnN2v_sin", "GLIBC_2.22", sh_vector_sin),
        SH_FUNCTION("_ZGVnN2v_log", "GLIBC_2.22", sh_vector_log),
        SH_FUNCTION("_ZGVnN2v_log2", "GLIBC_2.35", sh_vector_log2),
        SH_FUNCTION("_ZGVnN4v_cosf", "GLIBC_2.22", sh_vector_cosf),
        SH_FUNCTION("_ZGVnN4v_sinf", "GLIBC_2.22", sh_vector_sinf),
        SH_FUNCTION("_ZGVnN4v_acosf", "GLIBC_2.35", sh_vector_acosf),
        SH_FUNCTION("_ZGVnN4v_logf", "GLIBC_2.22", sh_vector_logf),
        SH_FUNCTION("_ZGVnN4v_expf", "GLIBC_2.22", sh_vector_expf),
        SH_FUNCTION("__sched_cpualloc", "GLIBC_2.7", sh_sched_cpualloc),
        SH_FUNCTION("__sched_cpufree", "GLIBC_2.7", sh_sched_cpufree),
        SH_FUNCTION("getttynam", "GLIBC_2.2.5", sh_getttynam),
        SH_FUNCTION("fts_open", "GLIBC_2.2.5", ftsOpen),
        SH_FUNCTION("fts_read", "GLIBC_2.2.5", ftsRead),
        SH_FUNCTION("fts_set", "GLIBC_2.2.5", ftsSet),
        SH_FUNCTION("fts_close", "GLIBC_2.2.5", ftsClose),
        SH_FUNCTION("fts64_open", "GLIBC_2.23", ftsOpen),
        SH_FUNCTION("fts64_read", "GLIBC_2.23", ftsRead),
        SH_FUNCTION("fts64_set", "GLIBC_2.23", ftsSet),
        SH_FUNCTION("fts64_close", "GLIBC_2.23", ftsClose),
        SH_FUNCTION("creat64", "GLIBC_2.2.5", sh_creat64),
        SH_FUNCTION("fallocate64", "GLIBC_2.10", sh_fallocate64),
        SH_FUNCTION("freopen64", "GLIBC_2.2.5", sh_freopen64),
        SH_FUNCTION("statvfs64", "GLIBC_2.2.5", sh_statvfs64),
        SH_FUNCTION("fstatvfs64", "GLIBC_2.2.5", sh_fstatvfs64),
        SH_FUNCTION("getrlimit64", "GLIBC_2.2.5", sh_getrlimit64),
        SH_FUNCTION("setrlimit64", "GLIBC_2.2.5", sh_setrlimit64),
        SH_FUNCTION("posix_fadvise64", "GLIBC_2.2.5", sh_posix_fadvise64),
        SH_FUNCTION("versionsort64", "GLIBC_2.2.5", sh_versionsort64),
        SH_FUNCTION("scandirat64", "GLIBC_2.15", sh_scandirat64),
        SH_FUNCTION("scandirat", "GLIBC_2.15", sh_scandirat64),
        SH_FUNCTION("malloc_trim", "GLIBC_2.2.5", sh_malloc_trim),
        SH_FUNCTION("mallinfo2", "GLIBC_2.33", sh_mallinfo2),
        SH_FUNCTION("strerrorname_np", "GLIBC_2.32", sh_strerrorname_np),
        SH_FUNCTION("rpmatch", "GLIBC_2.2.5", sh_rpmatch),
        SH_FUNCTION("getsgnam_r", "GLIBC_2.10", sh_getsgnam_r),
        SH_FUNCTION("__res_ninit", "GLIBC_2.2.5", sh_res_ninit),
        SH_FUNCTION("__res_nclose", "GLIBC_2.2.5", sh_res_nclose),
        SH_FUNCTION("res_nquery", "GLIBC_2.34", sh_res_nquery),
        SH_FUNCTION("parse_printf_format", "GLIBC_2.2.5", sh_parse_printf_format),
        SH_FUNCTION("regcomp", "GLIBC_2.2.5", sh_regcomp),
        SH_FUNCTION("regexec", "GLIBC_2.2.5", sh_regexec),
        SH_FUNCTION("regexec", "GLIBC_2.3.4", sh_regexec),
        SH_FUNCTION("regerror", "GLIBC_2.2.5", sh_regerror),
        SH_FUNCTION("regfree", "GLIBC_2.2.5", sh_regfree),
        SH_FUNCTION("nftw", "GLIBC_2.2.5", sh_nftw),
        SH_FUNCTION("nftw", "GLIBC_2.3.3", sh_nftw),
        SH_FUNCTION("nftw64", "GLIBC_2.2.5", sh_nftw),
        SH_FUNCTION("nftw64", "GLIBC_2.3.3", sh_nftw),
        SH_FUNCTION("pthread_getschedparam", "GLIBC_2.2.5", sh_pthread_getschedparam),
        SH_FUNCTION("pthread_attr_setschedparam", "GLIBC_2.2.5", sh_pthread_attr_setschedparam),
        SH_FUNCTION("pthread_attr_getschedparam", "GLIBC_2.2.5", sh_pthread_attr_getschedparam),
        SH_FUNCTION("abort", "GLIBC_2.2.5", abort),
        SH_FUNCTION("__errno_location", "GLIBC_2.2.5", sh_errno_location),
        SH_FUNCTION("strncpy", "GLIBC_2.2.5", strncpy),
        SH_FUNCTION("strncmp", "GLIBC_2.2.5", strncmp),
        SH_FUNCTION("secure_getenv", "GLIBC_2.17", sh_secure_getenv),
        SH_FUNCTION("arc4random", "GLIBC_2.36", sh_arc4random),
        SH_FUNCTION("arc4random_buf", "GLIBC_2.36", sh_arc4random_buf),
        SH_FUNCTION("__isoc23_sscanf", "GLIBC_2.38", sh_isoc23_sscanf),
        SH_FUNCTION("__isoc23_fscanf", "GLIBC_2.38", sh_isoc23_fscanf),
        SH_FUNCTION("__isoc23_scanf", "GLIBC_2.38", sh_isoc23_scanf),
        SH_FUNCTION("__isoc23_vsscanf", "GLIBC_2.38", sh_isoc23_vsscanf),
        SH_FUNCTION("__isoc23_strtoll", "GLIBC_2.38", sh_isoc23_strtoll),
        SH_FUNCTION("__isoc23_strtoull", "GLIBC_2.38", sh_isoc23_strtoull),
        SH_FUNCTION("__isoc23_wcstol", "GLIBC_2.38", sh_isoc23_wcstol),
        SH_FUNCTION("qsort", "GLIBC_2.2.5", qsort),
        SH_FUNCTION("fread", "GLIBC_2.2.5", fread),
        SH_FUNCTION("strtod", "GLIBC_2.2.5", strtod),
        SH_FUNCTION("readlink", "GLIBC_2.2.5", readlink),
        SH_FUNCTION("fclose", "GLIBC_2.2.5", fclose),
        SH_FUNCTION("opendir", "GLIBC_2.2.5", opendir),
        SH_FUNCTION("strlen", "GLIBC_2.2.5", strlen),
        SH_FUNCTION("__stack_chk_fail", "GLIBC_2.4", sh_stack_chk_fail),
        SH_FUNCTION("dladdr", "GLIBC_2.34", sh_glibc_dladdr),
        SH_FUNCTION("strchr", "GLIBC_2.2.5", sh_strchr),
        SH_FUNCTION("pthread_mutex_destroy", "GLIBC_2.2.5", sh_pthread_mutex_destroy),
        SH_FUNCTION("snprintf", "GLIBC_2.2.5", snprintf),
        SH_FUNCTION("pthread_mutexattr_settype", "GLIBC_2.34", sh_pthread_mutexattr_settype),
        SH_FUNCTION("strrchr", "GLIBC_2.2.5", sh_strrchr),
        SH_FUNCTION("fputs", "GLIBC_2.2.5", fputs),
        SH_FUNCTION("memset", "GLIBC_2.2.5", memset),
        SH_FUNCTION("strncat", "GLIBC_2.2.5", strncat),
        SH_FUNCTION("closedir", "GLIBC_2.2.5", closedir),
        SH_FUNCTION("fputc", "GLIBC_2.2.5", fputc),
        SH_FUNCTION("strtok_r", "GLIBC_2.2.5", strtok_r),
        SH_FUNCTION("calloc", "GLIBC_2.2.5", calloc),
        SH_FUNCTION("posix_memalign", "GLIBC_2.2.5", posix_memalign),
        SH_FUNCTION("strcmp", "GLIBC_2.2.5", strcmp),
        SH_FUNCTION("dlopen", "GLIBC_2.34", sh_glibc_dlopen),
        SH_FUNCTION("__memcpy_chk", "GLIBC_2.3.4", sh_memcpy_chk),
        SH_FUNCTION("realpath", "GLIBC_2.3", realpath),
        SH_FUNCTION("memcpy", "GLIBC_2.14", memcpy),
        SH_FUNCTION("__isoc23_strtol", "GLIBC_2.38", sh_isoc23_strtol),
        SH_FUNCTION("fileno", "GLIBC_2.2.5", fileno),
        SH_FUNCTION("readdir", "GLIBC_2.2.5", readdir),
        SH_FUNCTION("pthread_mutex_unlock", "GLIBC_2.2.5", sh_pthread_mutex_unlock),
        SH_FUNCTION("malloc", "GLIBC_2.2.5", malloc),
        SH_FUNCTION("__vsnprintf_chk", "GLIBC_2.3.4", sh_vsnprintf_chk),
        SH_FUNCTION("__strncpy_chk", "GLIBC_2.3.4", sh_strncpy_chk),
        SH_FUNCTION("realloc", "GLIBC_2.2.5", realloc),
        SH_FUNCTION("memmove", "GLIBC_2.2.5", memmove),
        SH_FUNCTION("access", "GLIBC_2.2.5", access),
        SH_FUNCTION("fopen", "GLIBC_2.2.5", fopen),
        SH_FUNCTION("dlsym", "GLIBC_2.34", sh_glibc_dlsym),
        SH_FUNCTION("__memset_chk", "GLIBC_2.3.4", sh_memset_chk),
        SH_FUNCTION("__strncat_chk", "GLIBC_2.3.4", sh_strncat_chk),
        SH_FUNCTION("pthread_mutexattr_init", "GLIBC_2.34", sh_pthread_mutexattr_init),
        SH_FUNCTION("strerror", "GLIBC_2.2.5", strerror),
        SH_FUNCTION("dlclose", "GLIBC_2.34", sh_glibc_dlclose),
        SH_FUNCTION("dlvsym", "GLIBC_2.34", sh_glibc_dlvsym),
        SH_FUNCTION("dlinfo", "GLIBC_2.3.3", sh_glibc_dlinfo),
        SH_FUNCTION("dlinfo", "GLIBC_2.34", sh_glibc_dlinfo),
        SH_FUNCTION("pthread_mutex_init", "GLIBC_2.2.5", sh_pthread_mutex_init),
        SH_FUNCTION("fstat", "GLIBC_2.33", fstat),
        SH_FUNCTION("__cxa_finalize", "GLIBC_2.2.5", sh_cxa_finalize),
        SH_FUNCTION("__cxa_atexit", "GLIBC_2.2.5", sh_cxa_atexit),
        SH_FUNCTION("strstr", "GLIBC_2.2.5", sh_strstr),
        SH_FUNCTION("pthread_mutex_lock", "GLIBC_2.2.5", sh_pthread_mutex_lock),
        SH_FUNCTION("pthread_mutex_trylock", "GLIBC_2.2.5", sh_pthread_mutex_trylock),
        SH_FUNCTION("pthread_mutex_timedlock", "GLIBC_2.2.5", sh_pthread_mutex_timedlock),
        SH_FUNCTION("__ctype_tolower_loc", "GLIBC_2.3", sh_ctype_tolower_loc),
        SH_FUNCTION("__tls_get_addr", "GLIBC_2.3", elfTlsAddress),
        SH_FUNCTION("__cxa_thread_atexit_impl", "GLIBC_2.18", sh_cxa_thread_atexit_impl),
        SH_FUNCTION("pthread_mutexattr_destroy", "GLIBC_2.34", sh_pthread_mutexattr_destroy),
        SH_FUNCTION("pthread_once", "GLIBC_2.34", sh_pthread_once),
        SH_FUNCTION("pthread_condattr_init", "GLIBC_2.2.5", sh_pthread_condattr_init),
        SH_FUNCTION("pthread_condattr_setclock", "GLIBC_2.34", sh_pthread_condattr_setclock),
        SH_FUNCTION("pthread_condattr_destroy", "GLIBC_2.2.5", sh_pthread_condattr_destroy),
        SH_FUNCTION("pthread_cond_init", "GLIBC_2.3.2", sh_pthread_cond_init),
        SH_FUNCTION("pthread_cond_destroy", "GLIBC_2.3.2", sh_pthread_cond_destroy),
        SH_FUNCTION("pthread_cond_signal", "GLIBC_2.3.2", sh_pthread_cond_signal),
        SH_FUNCTION("pthread_cond_broadcast", "GLIBC_2.3.2", sh_pthread_cond_broadcast),
        SH_FUNCTION("pthread_cond_wait", "GLIBC_2.3.2", sh_pthread_cond_wait),
        SH_FUNCTION("pthread_cond_timedwait", "GLIBC_2.3.2", sh_pthread_cond_timedwait),
        SH_FUNCTION("pthread_rwlock_init", "GLIBC_2.34", sh_pthread_rwlock_init),
        SH_FUNCTION("pthread_rwlock_destroy", "GLIBC_2.34", sh_pthread_rwlock_destroy),
        SH_FUNCTION("pthread_rwlock_rdlock", "GLIBC_2.34", sh_pthread_rwlock_rdlock),
        SH_FUNCTION("pthread_rwlock_wrlock", "GLIBC_2.34", sh_pthread_rwlock_wrlock),
        SH_FUNCTION("pthread_rwlock_unlock", "GLIBC_2.34", sh_pthread_rwlock_unlock),
        SH_FUNCTION("pthread_barrier_init", "GLIBC_2.34", sh_pthread_barrier_init),
        SH_FUNCTION("pthread_barrier_destroy", "GLIBC_2.34", sh_pthread_barrier_destroy),
        SH_FUNCTION("pthread_barrier_wait", "GLIBC_2.34", sh_pthread_barrier_wait),
        SH_FUNCTION("pthread_attr_init", "GLIBC_2.2.5", sh_pthread_attr_init),
        SH_FUNCTION("pthread_attr_destroy", "GLIBC_2.2.5", sh_pthread_attr_destroy),
        SH_FUNCTION("pthread_attr_setstacksize", "GLIBC_2.34", sh_pthread_attr_setstacksize),
        SH_FUNCTION("pthread_create", "GLIBC_2.34", sh_pthread_create),
        SH_FUNCTION("pthread_join", "GLIBC_2.34", sh_pthread_join),
        SH_FUNCTION("pthread_detach", "GLIBC_2.34", sh_pthread_detach),
        SH_FUNCTION("pthread_cancel", "GLIBC_2.34", sh_pthread_cancel),
        SH_FUNCTION("pthread_self", "GLIBC_2.2.5", sh_pthread_self),
        SH_FUNCTION("pthread_getname_np", "GLIBC_2.34", sh_pthread_getname_np),
        SH_FUNCTION("pthread_setname_np", "GLIBC_2.34", sh_pthread_setname_np),
        SH_FUNCTION("pthread_getaffinity_np", "GLIBC_2.32", sh_pthread_getaffinity_np),
        SH_FUNCTION("pthread_setaffinity_np", "GLIBC_2.34", sh_pthread_setaffinity_np),
        SH_FUNCTION("pthread_setschedparam", "GLIBC_2.2.5", sh_pthread_setschedparam),
        SH_FUNCTION("pthread_getspecific", "GLIBC_2.34", pthread_getspecific),
        SH_FUNCTION("pthread_setspecific", "GLIBC_2.34", pthread_setspecific),
        SH_FUNCTION("pthread_key_create", "GLIBC_2.34", pthread_key_create),
        SH_FUNCTION("pthread_key_delete", "GLIBC_2.34", pthread_key_delete),
        SH_FUNCTION("pthread_setcanceltype", "GLIBC_2.2.5", pthread_setcanceltype),
        SH_FUNCTION("pthread_sigmask", "GLIBC_2.32", pthread_sigmask),
        SH_FUNCTION("strerror_r", "GLIBC_2.2.5", sh_strerror_r),
        SH_FUNCTION("fopen64", "GLIBC_2.2.5", sh_fopen64),
        SH_FUNCTION("fseeko64", "GLIBC_2.2.5", sh_fseeko64),
        SH_FUNCTION("ftello64", "GLIBC_2.2.5", sh_ftello64),
        SH_FUNCTION("open64", "GLIBC_2.2.5", sh_open64),
        SH_FUNCTION("openat64", "GLIBC_2.4", sh_openat64),
        SH_FUNCTION("__open64_2", "GLIBC_2.7", sh_open64_2),
        SH_FUNCTION("__openat64_2", "GLIBC_2.7", sh_openat64_2),
        SH_FUNCTION("__openat_2", "GLIBC_2.7", sh_openat64_2),
        SH_FUNCTION("fcntl64", "GLIBC_2.28", sh_fcntl64),
        SH_FUNCTION("stat64", "GLIBC_2.33", sh_stat64),
        SH_FUNCTION("lstat64", "GLIBC_2.33", sh_lstat64),
        SH_FUNCTION("fstat64", "GLIBC_2.33", sh_fstat64),
        SH_FUNCTION("fstatat64", "GLIBC_2.33", sh_fstatat64),
        SH_FUNCTION("statfs64", "GLIBC_2.2.5", sh_statfs64),
        SH_FUNCTION("fstatfs64", "GLIBC_2.2.5", sh_fstatfs64),
        SH_FUNCTION("lseek64", "GLIBC_2.2.5", sh_lseek64),
        SH_FUNCTION("pread64", "GLIBC_2.2.5", sh_pread64),
        SH_FUNCTION("pwrite64", "GLIBC_2.2.5", sh_pwrite64),
        SH_FUNCTION("ftruncate64", "GLIBC_2.2.5", sh_ftruncate64),
        SH_FUNCTION("posix_fallocate64", "GLIBC_2.2.5", sh_posix_fallocate64),
        SH_FUNCTION("mmap64", "GLIBC_2.2.5", sh_mmap64),
        SH_FUNCTION("mkstemp64", "GLIBC_2.2.5", sh_mkstemp64),
        SH_FUNCTION("mkostemp64", "GLIBC_2.7", sh_mkostemp64),
        SH_FUNCTION("mkstemps64", "GLIBC_2.11", sh_mkstemps64),
        SH_FUNCTION("readdir64", "GLIBC_2.2.5", sh_readdir64),
        SH_FUNCTION("alphasort64", "GLIBC_2.2.5", sh_alphasort64),
        SH_FUNCTION("scandir64", "GLIBC_2.2.5", sh_scandir64),
        SH_FUNCTION("__printf_chk", "GLIBC_2.3.4", sh_printf_chk),
        SH_FUNCTION("__fprintf_chk", "GLIBC_2.3.4", sh_fprintf_chk),
        SH_FUNCTION("__vfprintf_chk", "GLIBC_2.3.4", sh_vfprintf_chk),
        SH_FUNCTION("__sprintf_chk", "GLIBC_2.3.4", sh_sprintf_chk),
        SH_FUNCTION("__vsprintf_chk", "GLIBC_2.3.4", sh_vsprintf_chk),
        SH_FUNCTION("__asprintf_chk", "GLIBC_2.8", sh_asprintf_chk),
        SH_FUNCTION("__vasprintf_chk", "GLIBC_2.8", sh_vasprintf_chk),
        SH_FUNCTION("__fread_chk", "GLIBC_2.7", sh_fread_chk),
        SH_FUNCTION("__memmove_chk", "GLIBC_2.3.4", sh_memmove_chk),
        SH_FUNCTION("__strcpy_chk", "GLIBC_2.3.4", sh_strcpy_chk),
        SH_FUNCTION("__strlcpy_chk", "GLIBC_2.38", sh_strlcpy_chk),
        SH_FUNCTION("__read_chk", "GLIBC_2.4", sh_read_chk),
        SH_FUNCTION("__pread_chk", "GLIBC_2.4", sh_pread_chk),
        SH_FUNCTION("__readlinkat_chk", "GLIBC_2.5", sh_readlinkat_chk),
        SH_FUNCTION("__realpath_chk", "GLIBC_2.4", sh_realpath_chk),
        SH_FUNCTION("__explicit_bzero_chk", "GLIBC_2.25", sh_explicit_bzero_chk),
        SH_FUNCTION("__mbsrtowcs_chk", "GLIBC_2.4", sh_mbsrtowcs_chk),
        SH_FUNCTION("__mbstowcs_chk", "GLIBC_2.4", sh_mbstowcs_chk),
        SH_FUNCTION("__wcsncpy_chk", "GLIBC_2.4", sh_wcsncpy_chk),
        SH_FUNCTION("__wmemcpy_chk", "GLIBC_2.4", sh_wmemcpy_chk),
        SH_FUNCTION("__wmemset_chk", "GLIBC_2.4", sh_wmemset_chk),
    };
}

bool GlibcSymbolKey::operator==(const GlibcSymbolKey&) const noexcept = default;

size_t GlibcSymbolKeyHash::operator()(const GlibcSymbolKey& key) const noexcept {
    auto name = std::hash<std::string_view>()(key.name);
    auto version = std::hash<std::string_view>()(key.version);

    return splitMix64(name ^ version);
}

GlibcAdapter::GlibcAdapter()
    : libcSingleThreaded_(0)
    , tolowerPointer_(tolowerTable_ + 128)
    , toupperPointer_(toupperTable_ + 128)
    , ctypePointer_(ctypeTable_ + 128)
{
    for (int value = -128; value < 256; ++value) {
        const int index = value + 128;
        tolowerTable_[index] = value;
        toupperTable_[index] = value;
        ctypeTable_[index] = 0;

        if (value >= 'A' && value <= 'Z') {
            tolowerTable_[index] = value - 'A' + 'a';
        }
        if (value >= 'a' && value <= 'z') {
            toupperTable_[index] = value - 'a' + 'A';
        }
        if (value < 0) {
            continue;
        }

        unsigned short flags = 0;
        flags |= isupper(value) ? 0x0100 : 0;
        flags |= islower(value) ? 0x0200 : 0;
        flags |= isalpha(value) ? 0x0400 : 0;
        flags |= isdigit(value) ? 0x0800 : 0;
        flags |= isxdigit(value) ? 0x1000 : 0;
        flags |= isspace(value) ? 0x2000 : 0;
        flags |= isprint(value) ? 0x4000 : 0;
        flags |= isgraph(value) ? 0x8000 : 0;
        flags |= isblank(value) ? 0x0001 : 0;
        flags |= iscntrl(value) ? 0x0002 : 0;
        flags |= ispunct(value) ? 0x0004 : 0;
        flags |= isalnum(value) ? 0x0008 : 0;
        ctypeTable_[index] = flags;
    }

    sh_libc_stack_end = findStackEnd();

    providers_.byVersion.reserve(sizeof(sh_glibc_symbols) / sizeof(sh_glibc_symbols[0]));
    providers_.byName.reserve(sizeof(sh_glibc_symbols) / sizeof(sh_glibc_symbols[0]));
    for (const auto& symbol : sh_glibc_symbols) {
        // The hand-written versions are x86-64 glibc's. When the platform's
        // generated inventory knows the name but not that exact version, the
        // adapter is registered under the versions the platform's glibc
        // really exports. Names outside the inventory entirely (the GCC_ and
        // CXXABI families of libgcc and libstdc++) keep the hand-written
        // version: those ABIs do not vary per architecture.
        auto versions = glibcSymbolVersions(symbol.name);

        if (versions.empty() || std::find(versions.begin(), versions.end(), symbol.version) != versions.end()) {
            providers_.byVersion.emplace(GlibcSymbolKey{symbol.name, symbol.version}, symbol.address);
        } else {
            for (auto version : versions) {
                providers_.byVersion.emplace(GlibcSymbolKey{symbol.name, version}, symbol.address);
            }
        }
        providers_.byName.emplace(symbol.name, symbol.address);
    }

    static constexpr std::string_view overrideNames[] = {
        "__cxa_atexit",
        "__cxa_finalize",
        "__cxa_thread_atexit_impl",
        "_dl_find_object",
        "_Unwind_DeleteException",
        "_Unwind_GetDataRelBase",
        "_Unwind_GetIPInfo",
        "_Unwind_GetLanguageSpecificData",
        "_Unwind_GetRegionStart",
        "_Unwind_GetTextRelBase",
        "_Unwind_RaiseException",
        "_Unwind_Resume",
        "_Unwind_Resume_or_Rethrow",
        "_Unwind_SetGR",
        "_Unwind_SetIP",
        "alphasort64",
        "dl_iterate_phdr",
        "dladdr",
        "dlclose",
        "dlerror",
        "dlinfo",
        "dlopen",
        "dlsym",
        "dlvsym",
        "fstat64",
        "fstatat64",
        "fstatfs64",
        "lstat64",
        "nftw",
        "nftw64",
        "pthread_attr_destroy",
        "pthread_attr_getschedparam",
        "pthread_attr_init",
        "pthread_attr_setschedparam",
        "pthread_attr_setstacksize",
        "pthread_barrier_destroy",
        "pthread_barrier_init",
        "pthread_barrier_wait",
        "pthread_cancel",
        "pthread_cond_broadcast",
        "pthread_cond_destroy",
        "pthread_cond_init",
        "pthread_cond_signal",
        "pthread_cond_timedwait",
        "pthread_cond_wait",
        "pthread_condattr_destroy",
        "pthread_condattr_init",
        "pthread_condattr_setclock",
        "pthread_create",
        "pthread_detach",
        "pthread_getaffinity_np",
        "pthread_getname_np",
        "pthread_getschedparam",
        "pthread_join",
        "pthread_mutex_destroy",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_timedlock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
        "pthread_mutexattr_destroy",
        "pthread_mutexattr_init",
        "pthread_mutexattr_settype",
        "pthread_once",
        "pthread_rwlock_destroy",
        "pthread_rwlock_init",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_unlock",
        "pthread_rwlock_wrlock",
        "pthread_self",
        "pthread_setaffinity_np",
        "pthread_setname_np",
        "pthread_setschedparam",
        "readdir64",
        "regcomp",
        "regerror",
        "regexec",
        "regfree",
        "scandir64",
        "stat64",
        "statfs64",
        "strerror_r",
    };

    overrideNames_.reserve(sizeof(overrideNames) / sizeof(overrideNames[0]));
    for (auto name : overrideNames) {
        overrideNames_.emplace(name);
    }
}

GlibcAdapter& GlibcAdapter::instance() {
    static auto* adapter = new GlibcAdapter();

    return *adapter;
}

const int** GlibcAdapter::ctypeTolower() {
    return &tolowerPointer_;
}

const int** GlibcAdapter::ctypeToupper() {
    return &toupperPointer_;
}

const unsigned short** GlibcAdapter::ctypeFlags() {
    return &ctypePointer_;
}

void* GlibcAdapter::libcSingleThreaded() {
    return &libcSingleThreaded_;
}

bool GlibcAdapter::hasSymbolVersion(std::string_view name, std::string_view version) const {
    return providers_.byVersion.contains({name, version}) || hasGlibcStub(name, version);
}

void* GlibcAdapter::findOverride(std::string_view name, std::string_view version) const {
    if (!overrideNames_.contains(name)) {
        return nullptr;
    }
    if (!version.empty() && !hasSymbolVersion(name, version)) {
        return nullptr;
    }

    auto provider = providers_.byName.find(name);

    return provider == providers_.byName.end() ? nullptr : provider->second;
}

void* GlibcAdapter::findFallback(std::string_view name, std::string_view version) const {
    if (version.empty()) {
        auto provider = providers_.byName.find(name);

        return provider == providers_.byName.end() ? nullptr : provider->second;
    }

    auto provider = providers_.byVersion.find({name, version});
    if (provider != providers_.byVersion.end()) {
        return provider->second;
    }

    return resolveGlibcStub(name, version);
}

void* GlibcAdapter::resolveSymbol(std::string_view name, std::string_view version, bool weak) {
    // The oldest version any symbol carries on the architecture.
#if defined(__x86_64__)
    constexpr std::string_view baseline = "GLIBC_2.2.5";
#elif defined(__aarch64__)
    constexpr std::string_view baseline = "GLIBC_2.17";
#endif

    if (name == "stderr" && version == baseline) {
        return (void*)(uintptr_t)&stderr;
    }
    // The pre-2.1 stdio ABI: the _IO_2_1_* objects are the FILE structures
    // themselves, and musl lays its FILE out to serve the accessors compilers
    // inline (dev/abi-diff.txt notwithstanding: the read pointers, the
    // always-overflowing write end, and the EOF/ERR bits all line up).
    if (version == baseline) {
        if (name == "_IO_2_1_stdin_") {
            return stdin;
        }
        if (name == "_IO_2_1_stdout_") {
            return stdout;
        }
        if (name == "_IO_2_1_stderr_") {
            return stderr;
        }
    }
    if (name == "__libc_single_threaded" && version == "GLIBC_2.32") {
        return libcSingleThreaded();
    }
    if (name == "_ITM_deregisterTMCloneTable" || name == "_ITM_registerTMCloneTable" || name == "__gmon_start__") {
        return nullptr;
    }
    if (auto* address = findOverride(name, version); address) {
        return address;
    }

    std::string symbolName(name);
    auto* libcHandle = stub_dlopen("c", RTLD_LOCAL);
    auto* hostAddress = libcHandle ? stub_dlsym(libcHandle, symbolName.c_str()) : nullptr;

    if (hostAddress) {
        return hostAddress;
    }
    stub_dlerror();
    if (auto* address = findFallback(name, version); address) {
        return address;
    }
    if (!weak) {
        fprintf(stderr, "glibc bridge: no ABI thunk for %.*s%.*s%.*s\n", static_cast<int>(name.size()), name.data(), version.empty() ? 0 : 1, "@", static_cast<int>(version.size()), version.data());
    }

    return nullptr;
}

void* dyn::resolveGlibcSymbol(std::string_view name, std::string_view version, bool weak) {
    return GlibcAdapter::instance().resolveSymbol(name, version, weak);
}

void* dyn::resolveGlibcOverride(std::string_view name, std::string_view version) {
    return GlibcAdapter::instance().findOverride(name, version);
}
