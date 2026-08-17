// The bridge defines _dl_find_object itself, with its own result type; hide the
// declaration a host <dlfcn.h> makes so the two cannot collide.
#define _dl_find_object sh_host_dl_find_object

#include "glibc_shim.h"

#include <link.h>

#include "dlfcn.h"
#include "elf_loader.h"
#include "glibc_stubs.h"
#include "hash.h"
#include "thread_tls.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <malloc.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
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
#include <sys/stat.h>
#include <sys/statfs.h>
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

        unsigned char libcSingleThreaded_;
        int tolowerTable_[384];
        const int* tolowerPointer_;
        int toupperTable_[384];
        const int* toupperPointer_;
        unsigned short ctypeTable_[384];
        const unsigned short* ctypePointer_;

        GlibcProviders providers_;
        std::unordered_set<std::string_view> overrideNames_;
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

    static int sh_pthread_create(uintptr_t* foreign_thread, const void* foreign_attributes, void* (*start)(void*), void* argument) {
        if (sh_trace_enabled()) {
            fprintf(stderr, "glibc bridge: pthread_create(start=%p, argument=%p)\n", (void*)(uintptr_t)start, argument);
        }

        pthread_t thread;
        const int result = pthread_create(&thread, static_cast<const pthread_attr_t*>(foreign_attributes), start, argument);

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

    struct GlibcHandle {
        explicit GlibcHandle(void* stubHandle);
        virtual ~GlibcHandle() noexcept;

        virtual void* lookup(std::string_view name, std::string_view version) const = 0;

        void* stubHandle_;
    };

    struct GlibcRuntimeHandle final: public GlibcHandle {
        explicit GlibcRuntimeHandle(void* stubHandle);

        void* lookup(std::string_view name, std::string_view version) const override;
    };

    struct GlibcStubLoaderHandle final: public GlibcHandle {
        explicit GlibcStubLoaderHandle(void* stubHandle);

        void* lookup(std::string_view name, std::string_view version) const override;
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

GlibcHandle::GlibcHandle(void* stubHandle)
    : stubHandle_(stubHandle)
{
}

GlibcHandle::~GlibcHandle() noexcept {
    stub_dlclose(stubHandle_);
}

GlibcRuntimeHandle::GlibcRuntimeHandle(void* stubHandle)
    : GlibcHandle(stubHandle)
{
}

void* GlibcRuntimeHandle::lookup(std::string_view name, std::string_view version) const {
    auto& adapter = GlibcAdapter::instance();

    if (!version.empty() && !adapter.hasSymbolVersion(name, version)) {
        return nullptr;
    }
    if (auto* address = adapter.findOverride(name, version); address) {
        return address;
    }
    if (auto* address = lookupStub(stubHandle_, name); address) {
        return address;
    }
    consumeStubError();
    if (auto* address = lookupLibc(name); address) {
        return address;
    }
    consumeStubError();

    return adapter.findFallback(name, version);
}

GlibcStubLoaderHandle::GlibcStubLoaderHandle(void* stubHandle)
    : GlibcHandle(stubHandle)
{
}

void* GlibcStubLoaderHandle::lookup(std::string_view name, std::string_view version) const {
    auto& adapter = GlibcAdapter::instance();

    if (auto* address = lookupStub(stubHandle_, name); address) {
        return address;
    }
    consumeStubError();
    if (auto* address = adapter.findOverride(name, version); address) {
        return address;
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

        auto translated = sh_translate_dlopen_flags(flags);
        auto* provider = path ? runtimeProvider(path) : "";
        auto runtime = provider != nullptr;
        auto* handle = stub_dlopen(runtime ? provider : path, translated);

        if (!handle) {
            copyStubError("library not found");
            return nullptr;
        }

        try {
            if (runtime) {
                return new GlibcRuntimeHandle(handle);
            }

            return new GlibcStubLoaderHandle(handle);
        } catch (const std::exception& error) {
            ThreadTls::current()->setDlError(error.what());
        } catch (...) {
            ThreadTls::current()->setDlError("unknown dlopen error");
        }

        return nullptr;
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
            auto* defaultHandle = stub_dlopen("", RTLD_LOCAL);
            GlibcRuntimeHandle runtime(defaultHandle);

            address = runtime.lookup(name, {});
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
            auto* defaultHandle = stub_dlopen("", RTLD_LOCAL);
            GlibcRuntimeHandle runtime(defaultHandle);

            address = runtime.lookup(name, version);
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

        delete reinterpret_cast<GlibcHandle*>(handle);

        return 0;
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

    providers_.byVersion.reserve(sizeof(sh_glibc_symbols) / sizeof(sh_glibc_symbols[0]));
    providers_.byName.reserve(sizeof(sh_glibc_symbols) / sizeof(sh_glibc_symbols[0]));
    for (const auto& symbol : sh_glibc_symbols) {
        providers_.byVersion.emplace(GlibcSymbolKey{symbol.name, symbol.version}, symbol.address);
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
        "dlopen",
        "dlsym",
        "dlvsym",
        "fstat64",
        "fstatat64",
        "fstatfs64",
        "lstat64",
        "pthread_attr_destroy",
        "pthread_attr_init",
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
    if (name == "stderr" && version == "GLIBC_2.2.5") {
        return (void*)(uintptr_t)&stderr;
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
