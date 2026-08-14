#if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
#endif

#include "glibc_shim.h"

#include "dlfcn.h"
#include "elf_loader.h"
#include "glibc_stubs.h"
#include "hash.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <libgen.h>
#include <link.h>
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

#include <string>
#include <string_view>
#include <unordered_map>

typedef struct {
    const char* name;
    const char* version;
    void* address;
} ShGlibcSymbol;

extern "C" int __cxa_atexit(void (*function)(void*), void* argument, void* dso);

#define SH_FUNCTION(name, version, function) {name, version, (void*)(uintptr_t)(function)}

#define SH_OBJECT(name, version, object) {name, version, (void*)(uintptr_t)(&(object))}

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

__attribute__((noreturn)) static void sh_stack_chk_fail(void) {
    abort();
}

static void sh_cxa_finalize(void* handle) {
    (void)handle;
}

static int sh_cxa_atexit(void (*function)(void*), void* argument, void* dso) {
    return __cxa_atexit(function, argument, dso);
}

__attribute__((noreturn)) void sh_glibc_unimplemented(const char* name) {
    fprintf(stderr, "glibc bridge: called unimplemented ABI thunk %s\n", name);
    abort();
}

static unsigned char sh_libc_single_threaded;

static int sh_tolower_table[384];
static const int* sh_tolower_pointer = sh_tolower_table + 128;
static pthread_once_t sh_tolower_once = PTHREAD_ONCE_INIT;

static void sh_initialize_tolower(void) {
    for (int value = -128; value < 256; ++value) {
        sh_tolower_table[value + 128] = value;
    }
    for (int value = 'A'; value <= 'Z'; ++value) {
        sh_tolower_table[value + 128] = value - 'A' + 'a';
    }
}

static const int** sh_ctype_tolower_loc(void) {
    pthread_once(&sh_tolower_once, sh_initialize_tolower);
    return &sh_tolower_pointer;
}

static int sh_toupper_table[384];
static const int* sh_toupper_pointer = sh_toupper_table + 128;
static unsigned short sh_ctype_table[384];
static const unsigned short* sh_ctype_pointer = sh_ctype_table + 128;
static pthread_once_t sh_ctype_once = PTHREAD_ONCE_INIT;

static void sh_initialize_ctype(void) {
    for (int value = -128; value < 256; ++value) {
        const int index = value + 128;
        sh_toupper_table[index] = value;
        if (value >= 'a' && value <= 'z') {
            sh_toupper_table[index] = value - 'a' + 'A';
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
        sh_ctype_table[index] = flags;
    }
}

static const int** sh_ctype_toupper_loc(void) {
    pthread_once(&sh_ctype_once, sh_initialize_ctype);
    return &sh_toupper_pointer;
}

static const unsigned short** sh_ctype_b_loc(void) {
    pthread_once(&sh_ctype_once, sh_initialize_ctype);
    return &sh_ctype_pointer;
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

struct ShDlIterateContext {
    int (*callback)(dl_phdr_info*, size_t, void*);
    void* data;
};

static int sh_visit_elf_headers(const ElfProgramHeaders& image, void* opaque) {
    auto& context = *static_cast<ShDlIterateContext*>(opaque);
    dl_phdr_info info{};
    info.dlpi_addr = image.base;
    info.dlpi_name = image.path;
    info.dlpi_phdr = image.headers;
    info.dlpi_phnum = image.count;
    info.dlpi_tls_modid = image.tlsModule;
    info.dlpi_tls_data = image.tlsData;

    return context.callback(&info, sizeof(info), context.data);
}

static int sh_dl_iterate_phdr(int (*callback)(dl_phdr_info*, size_t, void*), void* data) {
    const int hostResult = dl_iterate_phdr(callback, data);
    if (hostResult) {
        return hostResult;
    }

    ShDlIterateContext context{callback, data};
    return ElfImage::iterateProgramHeaders(sh_visit_elf_headers, &context);
}

enum {
    SH_MAX_FOREIGN_MUTEXES = 512
};

typedef struct {
    void* foreign;
    pthread_mutex_t host;
    int used;
} ShForeignMutex;

static pthread_mutex_t sh_mutex_table_lock = PTHREAD_MUTEX_INITIALIZER;
static ShForeignMutex sh_mutex_table[SH_MAX_FOREIGN_MUTEXES];

static ShForeignMutex* sh_find_mutex(void* foreign, int create, int type) {
    ShForeignMutex* free_slot = NULL;
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignMutex* slot = &sh_mutex_table[index];
        if (slot->used && slot->foreign == foreign) {
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return slot;
        }
        if (!slot->used && !free_slot) {
            free_slot = slot;
        }
    }
    if (!create || !free_slot) {
        pthread_mutex_unlock(&sh_mutex_table_lock);
        return NULL;
    }

    /* glibc's static recursive/error-check initializers encode __kind at
       byte offset 16 of pthread_mutex_t. Explicit pthread_mutex_init calls
       pass the translated attribute instead. */
    if (type < 0) {
        type = ((const int*)foreign)[4] & 3;
    }

    pthread_mutexattr_t attributes;
    pthread_mutexattr_init(&attributes);
    if (type == 1) {
        pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
    }
    if (type == 2) {
        pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_ERRORCHECK);
    }
    int result = pthread_mutex_init(&free_slot->host, &attributes);
    pthread_mutexattr_destroy(&attributes);
    if (result != 0) {
        pthread_mutex_unlock(&sh_mutex_table_lock);
        return NULL;
    }
    free_slot->foreign = foreign;
    free_slot->used = 1;
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return free_slot;
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
    int type = foreign_attributes ? *(const int*)foreign_attributes : 0;
    return sh_find_mutex(foreign, 1, type) ? 0 : ENOMEM;
}

static int sh_pthread_mutex_destroy(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignMutex* slot = &sh_mutex_table[index];
        if (slot->used && slot->foreign == foreign) {
            int result = pthread_mutex_destroy(&slot->host);
            if (result == 0) {
                slot->used = 0;
                slot->foreign = NULL;
            }
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return 0;
}

static int sh_pthread_mutex_lock(void* foreign) {
    ShForeignMutex* slot = sh_find_mutex(foreign, 1, -1);
    return slot ? pthread_mutex_lock(&slot->host) : ENOMEM;
}

static int sh_pthread_mutex_unlock(void* foreign) {
    ShForeignMutex* slot = sh_find_mutex(foreign, 0, 0);
    return slot ? pthread_mutex_unlock(&slot->host) : EINVAL;
}

static int sh_pthread_mutexattr_destroy(void* foreign_attributes) {
    (void)foreign_attributes;
    return 0;
}

typedef struct {
    void* foreign;
    pthread_once_t host;
    int used;
} ShForeignOnce;

static ShForeignOnce sh_once_table[SH_MAX_FOREIGN_MUTEXES];

static int sh_trace_enabled(void) {
    return getenv("SH_GLIBC_BRIDGE_TRACE") != NULL;
}

static int sh_pthread_once(void* foreign, void (*initialize)(void)) {
    if (sh_trace_enabled()) {
        fprintf(stderr, "glibc bridge: pthread_once(%p, %p)\n", foreign, (void*)(uintptr_t)initialize);
    }
    ShForeignOnce* slot = NULL;
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        if (sh_once_table[index].used && sh_once_table[index].foreign == foreign) {
            slot = &sh_once_table[index];
            break;
        }
        if (!sh_once_table[index].used && !slot) {
            slot = &sh_once_table[index];
        }
    }
    if (slot && !slot->used) {
        pthread_once_t initial = PTHREAD_ONCE_INIT;
        slot->host = initial;
        slot->foreign = foreign;
        slot->used = 1;
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return slot ? pthread_once(&slot->host, initialize) : ENOMEM;
}

typedef struct {
    void* foreign;
    pthread_cond_t host;
    int used;
} ShForeignCondition;

static ShForeignCondition sh_condition_table[SH_MAX_FOREIGN_MUTEXES];

static ShForeignCondition* sh_find_condition(void* foreign, int create, const void* foreign_attributes) {
    ShForeignCondition* free_slot = NULL;
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignCondition* slot = &sh_condition_table[index];
        if (slot->used && slot->foreign == foreign) {
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return slot;
        }
        if (!slot->used && !free_slot) {
            free_slot = slot;
        }
    }
    if (!create || !free_slot) {
        pthread_mutex_unlock(&sh_mutex_table_lock);
        return NULL;
    }
    pthread_condattr_t attributes;
    pthread_condattr_t* attributes_pointer = NULL;
    if (foreign_attributes) {
        pthread_condattr_init(&attributes);
        pthread_condattr_setclock(&attributes, *(const int*)foreign_attributes);
        attributes_pointer = &attributes;
    }
    int result = pthread_cond_init(&free_slot->host, attributes_pointer);
    if (attributes_pointer) {
        pthread_condattr_destroy(attributes_pointer);
    }
    if (result != 0) {
        pthread_mutex_unlock(&sh_mutex_table_lock);
        return NULL;
    }
    free_slot->foreign = foreign;
    free_slot->used = 1;
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return free_slot;
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
    return sh_find_condition(foreign, 1, foreign_attributes) ? 0 : ENOMEM;
}

static int sh_pthread_cond_destroy(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignCondition* slot = &sh_condition_table[index];
        if (slot->used && slot->foreign == foreign) {
            int result = pthread_cond_destroy(&slot->host);
            if (result == 0) {
                slot->used = 0;
                slot->foreign = NULL;
            }
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return 0;
}

static int sh_pthread_cond_signal(void* foreign) {
    ShForeignCondition* slot = sh_find_condition(foreign, 1, NULL);
    return slot ? pthread_cond_signal(&slot->host) : ENOMEM;
}

static int sh_pthread_cond_broadcast(void* foreign) {
    ShForeignCondition* slot = sh_find_condition(foreign, 1, NULL);
    return slot ? pthread_cond_broadcast(&slot->host) : ENOMEM;
}

static int sh_pthread_cond_wait(void* foreign_condition, void* foreign_mutex) {
    ShForeignCondition* condition = sh_find_condition(foreign_condition, 1, NULL);
    ShForeignMutex* mutex = sh_find_mutex(foreign_mutex, 1, -1);
    return condition && mutex ? pthread_cond_wait(&condition->host, &mutex->host) : ENOMEM;
}

static int sh_pthread_cond_timedwait(void* foreign_condition, void* foreign_mutex, const struct timespec* deadline) {
    ShForeignCondition* condition = sh_find_condition(foreign_condition, 1, NULL);
    ShForeignMutex* mutex = sh_find_mutex(foreign_mutex, 1, -1);
    return condition && mutex ? pthread_cond_timedwait(&condition->host, &mutex->host, deadline) : ENOMEM;
}

typedef struct {
    void* foreign;
    pthread_rwlock_t host;
    int used;
} ShForeignRwlock;

static ShForeignRwlock sh_rwlock_table[SH_MAX_FOREIGN_MUTEXES];

static ShForeignRwlock* sh_find_rwlock(void* foreign, int create) {
    ShForeignRwlock* free_slot = NULL;
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignRwlock* slot = &sh_rwlock_table[index];
        if (slot->used && slot->foreign == foreign) {
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return slot;
        }
        if (!slot->used && !free_slot) {
            free_slot = slot;
        }
    }
    if (!create || !free_slot || pthread_rwlock_init(&free_slot->host, NULL) != 0) {
        pthread_mutex_unlock(&sh_mutex_table_lock);
        return NULL;
    }
    free_slot->foreign = foreign;
    free_slot->used = 1;
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return free_slot;
}

static int sh_pthread_rwlock_init(void* foreign, const void* attributes) {
    (void)attributes;
    return sh_find_rwlock(foreign, 1) ? 0 : ENOMEM;
}

static int sh_pthread_rwlock_destroy(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignRwlock* slot = &sh_rwlock_table[index];
        if (slot->used && slot->foreign == foreign) {
            int result = pthread_rwlock_destroy(&slot->host);
            if (result == 0) {
                slot->used = 0;
                slot->foreign = NULL;
            }
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return 0;
}

static int sh_pthread_rwlock_rdlock(void* foreign) {
    ShForeignRwlock* slot = sh_find_rwlock(foreign, 1);
    return slot ? pthread_rwlock_rdlock(&slot->host) : ENOMEM;
}

static int sh_pthread_rwlock_wrlock(void* foreign) {
    ShForeignRwlock* slot = sh_find_rwlock(foreign, 1);
    return slot ? pthread_rwlock_wrlock(&slot->host) : ENOMEM;
}

static int sh_pthread_rwlock_unlock(void* foreign) {
    ShForeignRwlock* slot = sh_find_rwlock(foreign, 0);
    return slot ? pthread_rwlock_unlock(&slot->host) : EINVAL;
}

typedef struct {
    void* foreign;
    pthread_barrier_t host;
    int used;
} ShForeignBarrier;

static ShForeignBarrier sh_barrier_table[SH_MAX_FOREIGN_MUTEXES];

static int sh_pthread_barrier_init(void* foreign, const void* attributes, unsigned count) {
    (void)attributes;
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        ShForeignBarrier* slot = &sh_barrier_table[index];
        if (!slot->used) {
            int result = pthread_barrier_init(&slot->host, NULL, count);
            if (result == 0) {
                slot->foreign = foreign;
                slot->used = 1;
            }
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return ENOMEM;
}

static ShForeignBarrier* sh_find_barrier(void* foreign) {
    for (size_t index = 0; index < SH_MAX_FOREIGN_MUTEXES; ++index) {
        if (sh_barrier_table[index].used && sh_barrier_table[index].foreign == foreign) {
            return &sh_barrier_table[index];
        }
    }
    return NULL;
}

static int sh_pthread_barrier_wait(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    ShForeignBarrier* slot = sh_find_barrier(foreign);
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return slot ? pthread_barrier_wait(&slot->host) : EINVAL;
}

static int sh_pthread_barrier_destroy(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    ShForeignBarrier* slot = sh_find_barrier(foreign);
    int result = slot ? pthread_barrier_destroy(&slot->host) : 0;
    if (slot && result == 0) {
        slot->used = 0;
        slot->foreign = NULL;
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return result;
}

typedef struct {
    void* foreign;
    pthread_attr_t host;
    int used;
} ShForeignThreadAttributes;

static ShForeignThreadAttributes sh_thread_attribute_table[64];

static ShForeignThreadAttributes* sh_find_thread_attributes(void* foreign) {
    for (size_t index = 0; index < sizeof(sh_thread_attribute_table) / sizeof(sh_thread_attribute_table[0]); ++index) {
        if (sh_thread_attribute_table[index].used && sh_thread_attribute_table[index].foreign == foreign) {
            return &sh_thread_attribute_table[index];
        }
    }
    return NULL;
}

static int sh_pthread_attr_init(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    for (size_t index = 0; index < sizeof(sh_thread_attribute_table) / sizeof(sh_thread_attribute_table[0]); ++index) {
        ShForeignThreadAttributes* slot = &sh_thread_attribute_table[index];
        if (!slot->used) {
            int result = pthread_attr_init(&slot->host);
            if (result == 0) {
                slot->foreign = foreign;
                slot->used = 1;
            }
            pthread_mutex_unlock(&sh_mutex_table_lock);
            return result;
        }
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return ENOMEM;
}

static int sh_pthread_attr_destroy(void* foreign) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    ShForeignThreadAttributes* slot = sh_find_thread_attributes(foreign);
    int result = slot ? pthread_attr_destroy(&slot->host) : EINVAL;
    if (slot && result == 0) {
        slot->used = 0;
        slot->foreign = NULL;
    }
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return result;
}

static int sh_pthread_attr_setstacksize(void* foreign, size_t size) {
    pthread_mutex_lock(&sh_mutex_table_lock);
    ShForeignThreadAttributes* slot = sh_find_thread_attributes(foreign);
    int result = slot ? pthread_attr_setstacksize(&slot->host, size) : EINVAL;
    pthread_mutex_unlock(&sh_mutex_table_lock);
    return result;
}

static int sh_pthread_create(uintptr_t* foreign_thread, const void* foreign_attributes, void* (*start)(void*), void* argument) {
    if (sh_trace_enabled()) {
        fprintf(stderr, "glibc bridge: pthread_create(start=%p, argument=%p)\n", (void*)(uintptr_t)start, argument);
    }
    pthread_attr_t* host_attributes = NULL;
    if (foreign_attributes) {
        pthread_mutex_lock(&sh_mutex_table_lock);
        ShForeignThreadAttributes* slot = sh_find_thread_attributes((void*)foreign_attributes);
        if (slot) {
            host_attributes = &slot->host;
        }
        pthread_mutex_unlock(&sh_mutex_table_lock);
        if (!host_attributes) {
            return EINVAL;
        }
    }
    pthread_t thread;
    int result = pthread_create(&thread, host_attributes, start, argument);
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

typedef struct ShThreadDestructor {
    void (*function)(void*);
    void* argument;
    struct ShThreadDestructor* next;
} ShThreadDestructor;

static pthread_key_t sh_destructor_key;
static pthread_once_t sh_destructor_key_once = PTHREAD_ONCE_INIT;

static void sh_run_thread_destructors(void* opaque_list) {
    ShThreadDestructor* item = static_cast<ShThreadDestructor*>(opaque_list);
    while (item) {
        ShThreadDestructor* next = item->next;
        item->function(item->argument);
        free(item);
        item = next;
    }
}

static void sh_create_destructor_key(void) {
    if (pthread_key_create(&sh_destructor_key, sh_run_thread_destructors) != 0) {
        abort();
    }
}

static int sh_cxa_thread_atexit_impl(void (*function)(void*), void* argument, void* dso_handle) {
    (void)dso_handle;
    pthread_once(&sh_destructor_key_once, sh_create_destructor_key);
    ShThreadDestructor* item = static_cast<ShThreadDestructor*>(malloc(sizeof(*item)));
    if (!item) {
        return -1;
    }
    item->function = function;
    item->argument = argument;
    item->next = static_cast<ShThreadDestructor*>(pthread_getspecific(sh_destructor_key));
    if (pthread_setspecific(sh_destructor_key, item) != 0) {
        free(item);
        return -1;
    }
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

typedef struct {
    const char* filename;
    void* base;
    const char* symbol_name;
    void* symbol_address;
} ShGlibcDlInfo;

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
    if (!path) {
        return stub_dlopen("", sh_translate_dlopen_flags(flags));
    }
    return stub_dlopen(path, sh_translate_dlopen_flags(flags));
}

static void* sh_glibc_dlsym(void* handle, const char* name) {
    if (!handle || handle == (void*)(uintptr_t)-1) {
        stub_dlsym(NULL, name);
        return NULL;
    }
    return stub_dlsym(handle, name);
}

static void* sh_glibc_dlvsym(void* handle, const char* name, const char* version) {
    (void)version;
    return sh_glibc_dlsym(handle, name);
}

static int sh_glibc_dlclose(void* handle) {
    if (!handle || handle == (void*)(uintptr_t)-1) {
        return -1;
    }
    return stub_dlclose(handle);
}

static char* sh_glibc_dlerror(void) {
    return stub_dlerror();
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

static int sh_glibc_dladdr(const void* address, ShGlibcDlInfo* glibc_info) {
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

static const ShGlibcSymbol sh_glibc_symbols[] = {
    SH_FUNCTION("__getdelim", "GLIBC_2.2.5", getdelim),
    SH_FUNCTION("statfs", "GLIBC_2.2.5", statfs),
    SH_FUNCTION("fstatfs", "GLIBC_2.2.5", fstatfs),
    SH_FUNCTION("sigaction", "GLIBC_2.2.5", sigaction),
    SH_FUNCTION("nl_langinfo", "GLIBC_2.2.5", nl_langinfo),
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
    SH_FUNCTION("memrchr", "GLIBC_2.2.5", memrchr),
    SH_FUNCTION("__isoc99_fscanf", "GLIBC_2.7", fscanf),
    SH_FUNCTION("reallocarray", "GLIBC_2.26", reallocarray),
    SH_FUNCTION("strchrnul", "GLIBC_2.2.5", strchrnul),
    SH_FUNCTION("stpcpy", "GLIBC_2.2.5", stpcpy),
    SH_FUNCTION("__register_atfork", "GLIBC_2.3.2", sh_register_atfork),
    SH_FUNCTION("malloc_usable_size", "GLIBC_2.2.5", malloc_usable_size),
    SH_FUNCTION("__fsetlocking", "GLIBC_2.2.5", __fsetlocking),
    SH_FUNCTION("statx", "GLIBC_2.28", statx),
    SH_FUNCTION("__syslog_chk", "GLIBC_2.4", sh_syslog_chk),
    SH_FUNCTION("clock_nanosleep", "GLIBC_2.17", clock_nanosleep),
    SH_FUNCTION("dl_iterate_phdr", "GLIBC_2.2.5", sh_dl_iterate_phdr),
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
    SH_FUNCTION("dlerror", "GLIBC_2.34", sh_glibc_dlerror),
    SH_FUNCTION("free", "GLIBC_2.2.5", free),
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
    SH_FUNCTION("strchr", "GLIBC_2.2.5", static_cast<char* (*)(const char*, int)>(strchr)),
    SH_FUNCTION("pthread_mutex_destroy", "GLIBC_2.2.5", sh_pthread_mutex_destroy),
    SH_FUNCTION("snprintf", "GLIBC_2.2.5", snprintf),
    SH_FUNCTION("pthread_mutexattr_settype", "GLIBC_2.34", sh_pthread_mutexattr_settype),
    SH_FUNCTION("strrchr", "GLIBC_2.2.5", static_cast<char* (*)(const char*, int)>(strrchr)),
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
    SH_FUNCTION("strstr", "GLIBC_2.2.5", static_cast<char* (*)(const char*, const char*)>(strstr)),
    SH_FUNCTION("pthread_mutex_lock", "GLIBC_2.2.5", sh_pthread_mutex_lock),
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

struct ShGlibcKey {
    std::string_view name;
    std::string_view version;

    bool operator==(const ShGlibcKey&) const noexcept = default;
};

struct ShGlibcKeyHash {
    size_t operator()(const ShGlibcKey& key) const noexcept {
        auto name = std::hash<std::string_view>()(key.name);
        auto version = std::hash<std::string_view>()(key.version);

        return splitMix64(name ^ version);
    }
};

static const auto& sh_glibc_providers() {
    using Providers = std::unordered_map<ShGlibcKey, void*, ShGlibcKeyHash>;
    static const auto* providers = [] {
        auto* result = new Providers();

        result->reserve(sizeof(sh_glibc_symbols) / sizeof(sh_glibc_symbols[0]));
        for (const auto& symbol : sh_glibc_symbols) {
            result->emplace(ShGlibcKey{symbol.name, symbol.version}, symbol.address);
        }

        return result;
    }();

    return *providers;
}

void* resolveGlibcSymbol(const std::string_view& name, const std::string_view& version, bool weak) {
    if (name == "stderr" && version == "GLIBC_2.2.5") {
        return (void*)(uintptr_t)&stderr;
    }
    if (name == "__libc_single_threaded" && version == "GLIBC_2.32") {
        return &sh_libc_single_threaded;
    }
    if (name == "_ITM_deregisterTMCloneTable" || name == "_ITM_registerTMCloneTable" || name == "__gmon_start__") {
        return NULL;
    }
    const auto& providers = sh_glibc_providers();
    if (auto provider = providers.find({name, version}); provider != providers.end()) {
        return provider->second;
    }
    std::string symbolName(name);
    void* libc_handle = stub_dlopen("c", RTLD_LOCAL);
    void* host_address = libc_handle ? stub_dlsym(libc_handle, symbolName.c_str()) : NULL;
    if (host_address) {
        return host_address;
    }
    stub_dlerror();
    if (auto* stub = resolveGlibcStub(name, version); stub) {
        return stub;
    }
    if (!weak) {
        fprintf(stderr, "glibc bridge: no ABI thunk for %.*s%.*s%.*s\n", static_cast<int>(name.size()), name.data(), version.empty() ? 0 : 1, "@", static_cast<int>(version.size()), version.data());
    }
    return NULL;
}
