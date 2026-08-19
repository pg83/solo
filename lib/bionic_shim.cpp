#include "bionic_shim.h"
#include "glibc_shim.h"

#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wchar.h>

// The bionic personality: adapters for what Android's libc spells its own
// way. Termux packages are bionic-linked ELF DSOs whose system dependencies
// (libc.so, liblog.so, ...) the loader bridges here instead of loading, so a
// single musl runtime keeps serving the process. The table is demand-driven
// from the Termux mesa/vulkan closure, and everything bionic shares with
// glibc or plain POSIX rides the existing by-name providers.

extern "C" char* program_invocation_short_name;

namespace {
    // Bionic's stdio: the standard streams are the first three slots of the
    // exported __sF array (sizeof(struct __sFILE) == 152 on LP64), and
    // pre-NDK-r14 binaries still take their addresses. Every FILE* that
    // crosses the bridge is remapped from those slots onto musl's streams;
    // real musl FILE pointers pass through untouched.
    struct alignas(8) BionicFile {
        unsigned char opaque[152];
    };

    BionicFile bionicStandardStreams[3];

    static FILE* bionicStream(FILE* foreign) {
        auto* candidate = reinterpret_cast<BionicFile*>(foreign);

        if (candidate == &bionicStandardStreams[0]) {
            return stdin;
        }
        if (candidate == &bionicStandardStreams[1]) {
            return stdout;
        }
        if (candidate == &bionicStandardStreams[2]) {
            return stderr;
        }

        return foreign;
    }

    static int sh_fclose(FILE* stream) { return fclose(bionicStream(stream)); }
    static int sh_feof(FILE* stream) { return feof(bionicStream(stream)); }
    static int sh_ferror(FILE* stream) { return ferror(bionicStream(stream)); }
    static int sh_fflush(FILE* stream) { return fflush(stream ? bionicStream(stream) : stream); }
    static int sh_fgetc(FILE* stream) { return fgetc(bionicStream(stream)); }
    static char* sh_fgets(char* buffer, int size, FILE* stream) { return fgets(buffer, size, bionicStream(stream)); }
    static int sh_fileno(FILE* stream) { return fileno(bionicStream(stream)); }
    static int sh_fputc(int character, FILE* stream) { return fputc(character, bionicStream(stream)); }
    static int sh_fputs(const char* text, FILE* stream) { return fputs(text, bionicStream(stream)); }
    static wint_t sh_fputwc(wchar_t character, FILE* stream) { return fputwc(character, bionicStream(stream)); }
    static size_t sh_fread(void* buffer, size_t size, size_t count, FILE* stream) { return fread(buffer, size, count, bionicStream(stream)); }
    static int sh_fseek(FILE* stream, long offset, int whence) { return fseek(bionicStream(stream), offset, whence); }
    static int sh_fseeko(FILE* stream, off_t offset, int whence) { return fseeko(bionicStream(stream), offset, whence); }
    static long sh_ftell(FILE* stream) { return ftell(bionicStream(stream)); }
    static off_t sh_ftello(FILE* stream) { return ftello(bionicStream(stream)); }
    static size_t sh_fwrite(const void* buffer, size_t size, size_t count, FILE* stream) { return fwrite(buffer, size, count, bionicStream(stream)); }
    static int sh_getc(FILE* stream) { return getc(bionicStream(stream)); }
    static wint_t sh_getwc(FILE* stream) { return getwc(bionicStream(stream)); }
    static ssize_t sh_getline(char** line, size_t* capacity, FILE* stream) { return getline(line, capacity, bionicStream(stream)); }
    static void sh_clearerr(FILE* stream) { clearerr(bionicStream(stream)); }
    static int sh_putc(int character, FILE* stream) { return putc(character, bionicStream(stream)); }
    static void sh_rewind(FILE* stream) { rewind(bionicStream(stream)); }
    static void sh_setbuf(FILE* stream, char* buffer) { setbuf(bionicStream(stream), buffer); }
    static int sh_ungetc(int character, FILE* stream) { return ungetc(character, bionicStream(stream)); }
    static wint_t sh_ungetwc(wint_t character, FILE* stream) { return ungetwc(character, bionicStream(stream)); }
    static int sh_pclose(FILE* stream) { return pclose(bionicStream(stream)); }

    static int sh_vfprintf(FILE* stream, const char* format, va_list arguments) {
        return vfprintf(bionicStream(stream), format, arguments);
    }

    static int sh_fprintf(FILE* stream, const char* format, ...) {
        va_list arguments;
        va_start(arguments, format);
        auto result = vfprintf(bionicStream(stream), format, arguments);
        va_end(arguments);

        return result;
    }

    static int sh_fscanf(FILE* stream, const char* format, ...) {
        va_list arguments;
        va_start(arguments, format);
        auto result = vfscanf(bionicStream(stream), format, arguments);
        va_end(arguments);

        return result;
    }

    static int* sh_errno(void) {
        return &errno;
    }

    [[noreturn]] static void sh_assert2(const char* file, int line, const char* function, const char* message) {
        fprintf(stderr, "%s:%d: %s: assertion \"%s\" failed\n", file, line, function, message);
        abort();
    }

    static int sh_android_log_print(int priority, const char* tag, const char* format, ...) {
        fprintf(stderr, "%s: ", tag ? tag : "log");

        va_list arguments;
        va_start(arguments, format);
        vfprintf(stderr, format, arguments);
        va_end(arguments);
        fputc('\n', stderr);
        (void)priority;

        return 1;
    }

    static void sh_android_set_abort_message(const char* message) {
        (void)message;
    }

    static const void* sh_system_property_find(const char* name) {
        (void)name;

        return nullptr;
    }

    static int sh_register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void), void* dso) {
        (void)dso;

        return pthread_atfork(prepare, parent, child);
    }

    static void sh_fd_set_chk(int descriptor, fd_set* set, size_t set_size) {
        if (descriptor < 0 || descriptor >= FD_SETSIZE || set_size < sizeof(fd_set)) {
            fprintf(stderr, "bionic bridge: __FD_SET_chk out of bounds\n");
            abort();
        }
        FD_SET(descriptor, set);
    }

    static int sh_fd_isset_chk(int descriptor, const fd_set* set, size_t set_size) {
        if (descriptor < 0 || descriptor >= FD_SETSIZE || set_size < sizeof(fd_set)) {
            fprintf(stderr, "bionic bridge: __FD_ISSET_chk out of bounds\n");
            abort();
        }

        return FD_ISSET(descriptor, const_cast<fd_set*>(set));
    }

    static char* sh_gnu_strerror_r(int error, char* buffer, size_t size) {
        auto* text = strerror(error);

        if (!buffer || !size) {
            return text;
        }
        snprintf(buffer, size, "%s", text);

        return buffer;
    }

    static cmsghdr* sh_cmsg_nxthdr(msghdr* message, cmsghdr* control) {
        return CMSG_NXTHDR(message, control);
    }

    // Bionic's mallinfo carries size_t fields; honestly empty, like the
    // glibc pair.
    struct BionicMallinfo {
        size_t values[10];
    };

    static BionicMallinfo sh_mallinfo(void) {
        return {};
    }

    static const char* sh_getprogname(void) {
        return program_invocation_short_name;
    }

    // The strto*_l spellings musl does not export; the process runs in the
    // C/UTF-8 locale, so the locale argument selects nothing.
    static long long sh_strtoll_l(const char* text, char** end, int base, locale_t locale) {
        (void)locale;

        return strtoll(text, end, base);
    }

    static unsigned long long sh_strtoull_l(const char* text, char** end, int base, locale_t locale) {
        (void)locale;

        return strtoull(text, end, base);
    }

    static long double sh_strtold_l(const char* text, char** end, locale_t locale) {
        (void)locale;

        return strtold(text, end);
    }


    // Bionic numbers its sysconf selectors its own way (_SC_PAGESIZE is
    // 0x27 where musl says 30), so every query is translated by name. The
    // case values are bionic's bits/sysconf.h verbatim; a selector musl has
    // no name for answers -1/EINVAL.
    static long sh_sysconf(int selector) {
        switch (selector) {
#ifdef _SC_ARG_MAX
            case 0x0000: return sysconf(_SC_ARG_MAX);
#endif
#ifdef _SC_BC_BASE_MAX
            case 0x0001: return sysconf(_SC_BC_BASE_MAX);
#endif
#ifdef _SC_BC_DIM_MAX
            case 0x0002: return sysconf(_SC_BC_DIM_MAX);
#endif
#ifdef _SC_BC_SCALE_MAX
            case 0x0003: return sysconf(_SC_BC_SCALE_MAX);
#endif
#ifdef _SC_BC_STRING_MAX
            case 0x0004: return sysconf(_SC_BC_STRING_MAX);
#endif
#ifdef _SC_CHILD_MAX
            case 0x0005: return sysconf(_SC_CHILD_MAX);
#endif
#ifdef _SC_CLK_TCK
            case 0x0006: return sysconf(_SC_CLK_TCK);
#endif
#ifdef _SC_COLL_WEIGHTS_MAX
            case 0x0007: return sysconf(_SC_COLL_WEIGHTS_MAX);
#endif
#ifdef _SC_EXPR_NEST_MAX
            case 0x0008: return sysconf(_SC_EXPR_NEST_MAX);
#endif
#ifdef _SC_LINE_MAX
            case 0x0009: return sysconf(_SC_LINE_MAX);
#endif
#ifdef _SC_NGROUPS_MAX
            case 0x000a: return sysconf(_SC_NGROUPS_MAX);
#endif
#ifdef _SC_OPEN_MAX
            case 0x000b: return sysconf(_SC_OPEN_MAX);
#endif
#ifdef _SC_PASS_MAX
            case 0x000c: return sysconf(_SC_PASS_MAX);
#endif
#ifdef _SC_2_C_BIND
            case 0x000d: return sysconf(_SC_2_C_BIND);
#endif
#ifdef _SC_2_C_DEV
            case 0x000e: return sysconf(_SC_2_C_DEV);
#endif
#ifdef _SC_2_C_VERSION
            case 0x000f: return sysconf(_SC_2_C_VERSION);
#endif
#ifdef _SC_2_CHAR_TERM
            case 0x0010: return sysconf(_SC_2_CHAR_TERM);
#endif
#ifdef _SC_2_FORT_DEV
            case 0x0011: return sysconf(_SC_2_FORT_DEV);
#endif
#ifdef _SC_2_FORT_RUN
            case 0x0012: return sysconf(_SC_2_FORT_RUN);
#endif
#ifdef _SC_2_LOCALEDEF
            case 0x0013: return sysconf(_SC_2_LOCALEDEF);
#endif
#ifdef _SC_2_SW_DEV
            case 0x0014: return sysconf(_SC_2_SW_DEV);
#endif
#ifdef _SC_2_UPE
            case 0x0015: return sysconf(_SC_2_UPE);
#endif
#ifdef _SC_2_VERSION
            case 0x0016: return sysconf(_SC_2_VERSION);
#endif
#ifdef _SC_JOB_CONTROL
            case 0x0017: return sysconf(_SC_JOB_CONTROL);
#endif
#ifdef _SC_SAVED_IDS
            case 0x0018: return sysconf(_SC_SAVED_IDS);
#endif
#ifdef _SC_VERSION
            case 0x0019: return sysconf(_SC_VERSION);
#endif
#ifdef _SC_RE_DUP_MAX
            case 0x001a: return sysconf(_SC_RE_DUP_MAX);
#endif
#ifdef _SC_STREAM_MAX
            case 0x001b: return sysconf(_SC_STREAM_MAX);
#endif
#ifdef _SC_TZNAME_MAX
            case 0x001c: return sysconf(_SC_TZNAME_MAX);
#endif
#ifdef _SC_XOPEN_CRYPT
            case 0x001d: return sysconf(_SC_XOPEN_CRYPT);
#endif
#ifdef _SC_XOPEN_ENH_I18N
            case 0x001e: return sysconf(_SC_XOPEN_ENH_I18N);
#endif
#ifdef _SC_XOPEN_SHM
            case 0x001f: return sysconf(_SC_XOPEN_SHM);
#endif
#ifdef _SC_XOPEN_VERSION
            case 0x0020: return sysconf(_SC_XOPEN_VERSION);
#endif
#ifdef _SC_XOPEN_XCU_VERSION
            case 0x0021: return sysconf(_SC_XOPEN_XCU_VERSION);
#endif
#ifdef _SC_XOPEN_REALTIME
            case 0x0022: return sysconf(_SC_XOPEN_REALTIME);
#endif
#ifdef _SC_XOPEN_REALTIME_THREADS
            case 0x0023: return sysconf(_SC_XOPEN_REALTIME_THREADS);
#endif
#ifdef _SC_XOPEN_LEGACY
            case 0x0024: return sysconf(_SC_XOPEN_LEGACY);
#endif
#ifdef _SC_ATEXIT_MAX
            case 0x0025: return sysconf(_SC_ATEXIT_MAX);
#endif
#ifdef _SC_IOV_MAX
            case 0x0026: return sysconf(_SC_IOV_MAX);
#endif
#ifdef _SC_PAGESIZE
            case 0x0027: return sysconf(_SC_PAGESIZE);
#endif
#ifdef _SC_PAGE_SIZE
            case 0x0028: return sysconf(_SC_PAGE_SIZE);
#endif
#ifdef _SC_XOPEN_UNIX
            case 0x0029: return sysconf(_SC_XOPEN_UNIX);
#endif
#ifdef _SC_XBS5_ILP32_OFF32
            case 0x002a: return sysconf(_SC_XBS5_ILP32_OFF32);
#endif
#ifdef _SC_XBS5_ILP32_OFFBIG
            case 0x002b: return sysconf(_SC_XBS5_ILP32_OFFBIG);
#endif
#ifdef _SC_XBS5_LP64_OFF64
            case 0x002c: return sysconf(_SC_XBS5_LP64_OFF64);
#endif
#ifdef _SC_XBS5_LPBIG_OFFBIG
            case 0x002d: return sysconf(_SC_XBS5_LPBIG_OFFBIG);
#endif
#ifdef _SC_AIO_LISTIO_MAX
            case 0x002e: return sysconf(_SC_AIO_LISTIO_MAX);
#endif
#ifdef _SC_AIO_MAX
            case 0x002f: return sysconf(_SC_AIO_MAX);
#endif
#ifdef _SC_DELAYTIMER_MAX
            case 0x0031: return sysconf(_SC_DELAYTIMER_MAX);
#endif
#ifdef _SC_MQ_OPEN_MAX
            case 0x0032: return sysconf(_SC_MQ_OPEN_MAX);
#endif
#ifdef _SC_MQ_PRIO_MAX
            case 0x0033: return sysconf(_SC_MQ_PRIO_MAX);
#endif
#ifdef _SC_RTSIG_MAX
            case 0x0034: return sysconf(_SC_RTSIG_MAX);
#endif
#ifdef _SC_SEM_NSEMS_MAX
            case 0x0035: return sysconf(_SC_SEM_NSEMS_MAX);
#endif
#ifdef _SC_SEM_VALUE_MAX
            case 0x0036: return sysconf(_SC_SEM_VALUE_MAX);
#endif
#ifdef _SC_SIGQUEUE_MAX
            case 0x0037: return sysconf(_SC_SIGQUEUE_MAX);
#endif
#ifdef _SC_TIMER_MAX
            case 0x0038: return sysconf(_SC_TIMER_MAX);
#endif
#ifdef _SC_ASYNCHRONOUS_IO
            case 0x0039: return sysconf(_SC_ASYNCHRONOUS_IO);
#endif
#ifdef _SC_FSYNC
            case 0x003a: return sysconf(_SC_FSYNC);
#endif
#ifdef _SC_MAPPED_FILES
            case 0x003b: return sysconf(_SC_MAPPED_FILES);
#endif
#ifdef _SC_MEMLOCK
            case 0x003c: return sysconf(_SC_MEMLOCK);
#endif
#ifdef _SC_MEMLOCK_RANGE
            case 0x003d: return sysconf(_SC_MEMLOCK_RANGE);
#endif
#ifdef _SC_MEMORY_PROTECTION
            case 0x003e: return sysconf(_SC_MEMORY_PROTECTION);
#endif
#ifdef _SC_MESSAGE_PASSING
            case 0x003f: return sysconf(_SC_MESSAGE_PASSING);
#endif
#ifdef _SC_PRIORITIZED_IO
            case 0x0040: return sysconf(_SC_PRIORITIZED_IO);
#endif
#ifdef _SC_PRIORITY_SCHEDULING
            case 0x0041: return sysconf(_SC_PRIORITY_SCHEDULING);
#endif
#ifdef _SC_REALTIME_SIGNALS
            case 0x0042: return sysconf(_SC_REALTIME_SIGNALS);
#endif
#ifdef _SC_SEMAPHORES
            case 0x0043: return sysconf(_SC_SEMAPHORES);
#endif
#ifdef _SC_SHARED_MEMORY_OBJECTS
            case 0x0044: return sysconf(_SC_SHARED_MEMORY_OBJECTS);
#endif
#ifdef _SC_SYNCHRONIZED_IO
            case 0x0045: return sysconf(_SC_SYNCHRONIZED_IO);
#endif
#ifdef _SC_TIMERS
            case 0x0046: return sysconf(_SC_TIMERS);
#endif
#ifdef _SC_GETGR_R_SIZE_MAX
            case 0x0047: return sysconf(_SC_GETGR_R_SIZE_MAX);
#endif
#ifdef _SC_GETPW_R_SIZE_MAX
            case 0x0048: return sysconf(_SC_GETPW_R_SIZE_MAX);
#endif
#ifdef _SC_LOGIN_NAME_MAX
            case 0x0049: return sysconf(_SC_LOGIN_NAME_MAX);
#endif
#ifdef _SC_THREAD_DESTRUCTOR_ITERATIONS
            case 0x004a: return sysconf(_SC_THREAD_DESTRUCTOR_ITERATIONS);
#endif
#ifdef _SC_THREAD_KEYS_MAX
            case 0x004b: return sysconf(_SC_THREAD_KEYS_MAX);
#endif
#ifdef _SC_THREAD_STACK_MIN
            case 0x004c: return sysconf(_SC_THREAD_STACK_MIN);
#endif
#ifdef _SC_THREAD_THREADS_MAX
            case 0x004d: return sysconf(_SC_THREAD_THREADS_MAX);
#endif
#ifdef _SC_TTY_NAME_MAX
            case 0x004e: return sysconf(_SC_TTY_NAME_MAX);
#endif
#ifdef _SC_THREADS
            case 0x004f: return sysconf(_SC_THREADS);
#endif
#ifdef _SC_THREAD_ATTR_STACKADDR
            case 0x0050: return sysconf(_SC_THREAD_ATTR_STACKADDR);
#endif
#ifdef _SC_THREAD_ATTR_STACKSIZE
            case 0x0051: return sysconf(_SC_THREAD_ATTR_STACKSIZE);
#endif
#ifdef _SC_THREAD_PRIORITY_SCHEDULING
            case 0x0052: return sysconf(_SC_THREAD_PRIORITY_SCHEDULING);
#endif
#ifdef _SC_THREAD_PRIO_INHERIT
            case 0x0053: return sysconf(_SC_THREAD_PRIO_INHERIT);
#endif
#ifdef _SC_THREAD_PRIO_PROTECT
            case 0x0054: return sysconf(_SC_THREAD_PRIO_PROTECT);
#endif
#ifdef _SC_THREAD_SAFE_FUNCTIONS
            case 0x0055: return sysconf(_SC_THREAD_SAFE_FUNCTIONS);
#endif
#ifdef _SC_NPROCESSORS_CONF
            case 0x0060: return sysconf(_SC_NPROCESSORS_CONF);
#endif
#ifdef _SC_NPROCESSORS_ONLN
            case 0x0061: return sysconf(_SC_NPROCESSORS_ONLN);
#endif
#ifdef _SC_PHYS_PAGES
            case 0x0062: return sysconf(_SC_PHYS_PAGES);
#endif
#ifdef _SC_AVPHYS_PAGES
            case 0x0063: return sysconf(_SC_AVPHYS_PAGES);
#endif
#ifdef _SC_MONOTONIC_CLOCK
            case 0x0064: return sysconf(_SC_MONOTONIC_CLOCK);
#endif
#ifdef _SC_2_PBS
            case 0x0065: return sysconf(_SC_2_PBS);
#endif
#ifdef _SC_2_PBS_ACCOUNTING
            case 0x0066: return sysconf(_SC_2_PBS_ACCOUNTING);
#endif
#ifdef _SC_2_PBS_CHECKPOINT
            case 0x0067: return sysconf(_SC_2_PBS_CHECKPOINT);
#endif
#ifdef _SC_2_PBS_LOCATE
            case 0x0068: return sysconf(_SC_2_PBS_LOCATE);
#endif
#ifdef _SC_2_PBS_MESSAGE
            case 0x0069: return sysconf(_SC_2_PBS_MESSAGE);
#endif
#ifdef _SC_2_PBS_TRACK
            case 0x006a: return sysconf(_SC_2_PBS_TRACK);
#endif
#ifdef _SC_ADVISORY_INFO
            case 0x006b: return sysconf(_SC_ADVISORY_INFO);
#endif
#ifdef _SC_BARRIERS
            case 0x006c: return sysconf(_SC_BARRIERS);
#endif
#ifdef _SC_CLOCK_SELECTION
            case 0x006d: return sysconf(_SC_CLOCK_SELECTION);
#endif
#ifdef _SC_CPUTIME
            case 0x006e: return sysconf(_SC_CPUTIME);
#endif
#ifdef _SC_HOST_NAME_MAX
            case 0x006f: return sysconf(_SC_HOST_NAME_MAX);
#endif
#ifdef _SC_IPV6
            case 0x0070: return sysconf(_SC_IPV6);
#endif
#ifdef _SC_RAW_SOCKETS
            case 0x0071: return sysconf(_SC_RAW_SOCKETS);
#endif
#ifdef _SC_READER_WRITER_LOCKS
            case 0x0072: return sysconf(_SC_READER_WRITER_LOCKS);
#endif
#ifdef _SC_REGEXP
            case 0x0073: return sysconf(_SC_REGEXP);
#endif
#ifdef _SC_SHELL
            case 0x0074: return sysconf(_SC_SHELL);
#endif
#ifdef _SC_SPAWN
            case 0x0075: return sysconf(_SC_SPAWN);
#endif
#ifdef _SC_SPIN_LOCKS
            case 0x0076: return sysconf(_SC_SPIN_LOCKS);
#endif
#ifdef _SC_SPORADIC_SERVER
            case 0x0077: return sysconf(_SC_SPORADIC_SERVER);
#endif
#ifdef _SC_SS_REPL_MAX
            case 0x0078: return sysconf(_SC_SS_REPL_MAX);
#endif
#ifdef _SC_SYMLOOP_MAX
            case 0x0079: return sysconf(_SC_SYMLOOP_MAX);
#endif
#ifdef _SC_THREAD_CPUTIME
            case 0x007a: return sysconf(_SC_THREAD_CPUTIME);
#endif
#ifdef _SC_THREAD_PROCESS_SHARED
            case 0x007b: return sysconf(_SC_THREAD_PROCESS_SHARED);
#endif
#ifdef _SC_THREAD_ROBUST_PRIO_INHERIT
            case 0x007c: return sysconf(_SC_THREAD_ROBUST_PRIO_INHERIT);
#endif
#ifdef _SC_THREAD_ROBUST_PRIO_PROTECT
            case 0x007d: return sysconf(_SC_THREAD_ROBUST_PRIO_PROTECT);
#endif
#ifdef _SC_THREAD_SPORADIC_SERVER
            case 0x007e: return sysconf(_SC_THREAD_SPORADIC_SERVER);
#endif
#ifdef _SC_TIMEOUTS
            case 0x007f: return sysconf(_SC_TIMEOUTS);
#endif
#ifdef _SC_TRACE
            case 0x0080: return sysconf(_SC_TRACE);
#endif
#ifdef _SC_TRACE_EVENT_FILTER
            case 0x0081: return sysconf(_SC_TRACE_EVENT_FILTER);
#endif
#ifdef _SC_TRACE_EVENT_NAME_MAX
            case 0x0082: return sysconf(_SC_TRACE_EVENT_NAME_MAX);
#endif
#ifdef _SC_TRACE_INHERIT
            case 0x0083: return sysconf(_SC_TRACE_INHERIT);
#endif
#ifdef _SC_TRACE_LOG
            case 0x0084: return sysconf(_SC_TRACE_LOG);
#endif
#ifdef _SC_TRACE_NAME_MAX
            case 0x0085: return sysconf(_SC_TRACE_NAME_MAX);
#endif
#ifdef _SC_TRACE_SYS_MAX
            case 0x0086: return sysconf(_SC_TRACE_SYS_MAX);
#endif
#ifdef _SC_TRACE_USER_EVENT_MAX
            case 0x0087: return sysconf(_SC_TRACE_USER_EVENT_MAX);
#endif
#ifdef _SC_TYPED_MEMORY_OBJECTS
            case 0x0088: return sysconf(_SC_TYPED_MEMORY_OBJECTS);
#endif
#ifdef _SC_V7_ILP32_OFF32
            case 0x0089: return sysconf(_SC_V7_ILP32_OFF32);
#endif
#ifdef _SC_V7_ILP32_OFFBIG
            case 0x008a: return sysconf(_SC_V7_ILP32_OFFBIG);
#endif
#ifdef _SC_V7_LP64_OFF64
            case 0x008b: return sysconf(_SC_V7_LP64_OFF64);
#endif
#ifdef _SC_V7_LPBIG_OFFBIG
            case 0x008c: return sysconf(_SC_V7_LPBIG_OFFBIG);
#endif
#ifdef _SC_XOPEN_STREAMS
            case 0x008d: return sysconf(_SC_XOPEN_STREAMS);
#endif
#ifdef _SC_XOPEN_UUCP
            case 0x008e: return sysconf(_SC_XOPEN_UUCP);
#endif
#ifdef _SC_LEVEL1_ICACHE_SIZE
            case 0x008f: return sysconf(_SC_LEVEL1_ICACHE_SIZE);
#endif
#ifdef _SC_LEVEL1_ICACHE_ASSOC
            case 0x0090: return sysconf(_SC_LEVEL1_ICACHE_ASSOC);
#endif
#ifdef _SC_LEVEL1_ICACHE_LINESIZE
            case 0x0091: return sysconf(_SC_LEVEL1_ICACHE_LINESIZE);
#endif
#ifdef _SC_LEVEL1_DCACHE_SIZE
            case 0x0092: return sysconf(_SC_LEVEL1_DCACHE_SIZE);
#endif
#ifdef _SC_LEVEL1_DCACHE_ASSOC
            case 0x0093: return sysconf(_SC_LEVEL1_DCACHE_ASSOC);
#endif
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
            case 0x0094: return sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
#endif
#ifdef _SC_LEVEL2_CACHE_SIZE
            case 0x0095: return sysconf(_SC_LEVEL2_CACHE_SIZE);
#endif
#ifdef _SC_LEVEL2_CACHE_ASSOC
            case 0x0096: return sysconf(_SC_LEVEL2_CACHE_ASSOC);
#endif
#ifdef _SC_LEVEL2_CACHE_LINESIZE
            case 0x0097: return sysconf(_SC_LEVEL2_CACHE_LINESIZE);
#endif
#ifdef _SC_LEVEL3_CACHE_SIZE
            case 0x0098: return sysconf(_SC_LEVEL3_CACHE_SIZE);
#endif
#ifdef _SC_LEVEL3_CACHE_ASSOC
            case 0x0099: return sysconf(_SC_LEVEL3_CACHE_ASSOC);
#endif
#ifdef _SC_LEVEL3_CACHE_LINESIZE
            case 0x009a: return sysconf(_SC_LEVEL3_CACHE_LINESIZE);
#endif
#ifdef _SC_LEVEL4_CACHE_SIZE
            case 0x009b: return sysconf(_SC_LEVEL4_CACHE_SIZE);
#endif
#ifdef _SC_LEVEL4_CACHE_ASSOC
            case 0x009c: return sysconf(_SC_LEVEL4_CACHE_ASSOC);
#endif
#ifdef _SC_LEVEL4_CACHE_LINESIZE
            case 0x009d: return sysconf(_SC_LEVEL4_CACHE_LINESIZE);
#endif
#ifdef _SC_NSIG
            case 0x009e: return sysconf(_SC_NSIG);
#endif
        }
        errno = EINVAL;

        return -1;
    }


    // pathconf selectors, same story as sysconf: bionic numbers them from
    // zero in its own order.
    static long sh_translate_pc(int selector) {
        switch (selector) {
#ifdef _PC_FILESIZEBITS
            case 0: return _PC_FILESIZEBITS;
#endif
#ifdef _PC_LINK_MAX
            case 1: return _PC_LINK_MAX;
#endif
#ifdef _PC_MAX_CANON
            case 2: return _PC_MAX_CANON;
#endif
#ifdef _PC_MAX_INPUT
            case 3: return _PC_MAX_INPUT;
#endif
#ifdef _PC_NAME_MAX
            case 4: return _PC_NAME_MAX;
#endif
#ifdef _PC_PATH_MAX
            case 5: return _PC_PATH_MAX;
#endif
#ifdef _PC_PIPE_BUF
            case 6: return _PC_PIPE_BUF;
#endif
#ifdef _PC_2_SYMLINKS
            case 7: return _PC_2_SYMLINKS;
#endif
#ifdef _PC_ALLOC_SIZE_MIN
            case 8: return _PC_ALLOC_SIZE_MIN;
#endif
#ifdef _PC_REC_INCR_XFER_SIZE
            case 9: return _PC_REC_INCR_XFER_SIZE;
#endif
#ifdef _PC_REC_MAX_XFER_SIZE
            case 10: return _PC_REC_MAX_XFER_SIZE;
#endif
#ifdef _PC_REC_MIN_XFER_SIZE
            case 11: return _PC_REC_MIN_XFER_SIZE;
#endif
#ifdef _PC_REC_XFER_ALIGN
            case 12: return _PC_REC_XFER_ALIGN;
#endif
#ifdef _PC_SYMLINK_MAX
            case 13: return _PC_SYMLINK_MAX;
#endif
#ifdef _PC_CHOWN_RESTRICTED
            case 14: return _PC_CHOWN_RESTRICTED;
#endif
#ifdef _PC_NO_TRUNC
            case 15: return _PC_NO_TRUNC;
#endif
#ifdef _PC_VDISABLE
            case 16: return _PC_VDISABLE;
#endif
#ifdef _PC_ASYNC_IO
            case 17: return _PC_ASYNC_IO;
#endif
#ifdef _PC_PRIO_IO
            case 18: return _PC_PRIO_IO;
#endif
#ifdef _PC_SYNC_IO
            case 19: return _PC_SYNC_IO;
#endif
        }

        return -1;
    }

    static long sh_pathconf(const char* path, int selector) {
        auto translated = sh_translate_pc(selector);

        if (translated < 0) {
            errno = EINVAL;

            return -1;
        }

        return pathconf(path, translated);
    }

    static long sh_fpathconf(int descriptor, int selector) {
        auto translated = sh_translate_pc(selector);

        if (translated < 0) {
            errno = EINVAL;

            return -1;
        }

        return fpathconf(descriptor, translated);
    }

    // An unset property: empty value, zero length.
    static int sh_system_property_get(const char* name, char* value) {
        (void)name;
        if (value) {
            value[0] = 0;
        }

        return 0;
    }

    struct BionicSymbol {
        const char* name;
        void* address;
    };

#define BIONIC_FUNCTION(name, address) {name, reinterpret_cast<void*>(address)}

    static const BionicSymbol bionicSymbols[] = {
        {"__sF", bionicStandardStreams},
        BIONIC_FUNCTION("__errno", sh_errno),
        BIONIC_FUNCTION("__assert2", sh_assert2),
        BIONIC_FUNCTION("__android_log_print", sh_android_log_print),
        BIONIC_FUNCTION("android_set_abort_message", sh_android_set_abort_message),
        BIONIC_FUNCTION("__system_property_find", sh_system_property_find),
        BIONIC_FUNCTION("__register_atfork", sh_register_atfork),
        BIONIC_FUNCTION("__FD_SET_chk", sh_fd_set_chk),
        BIONIC_FUNCTION("__FD_ISSET_chk", sh_fd_isset_chk),
        BIONIC_FUNCTION("__gnu_strerror_r", sh_gnu_strerror_r),
        BIONIC_FUNCTION("__cmsg_nxthdr", sh_cmsg_nxthdr),
        BIONIC_FUNCTION("mallinfo", sh_mallinfo),
        BIONIC_FUNCTION("getprogname", sh_getprogname),
        BIONIC_FUNCTION("sysconf", sh_sysconf),
        BIONIC_FUNCTION("pathconf", sh_pathconf),
        BIONIC_FUNCTION("fpathconf", sh_fpathconf),
        BIONIC_FUNCTION("__system_property_get", sh_system_property_get),
        BIONIC_FUNCTION("strtoll_l", sh_strtoll_l),
        BIONIC_FUNCTION("strtoull_l", sh_strtoull_l),
        BIONIC_FUNCTION("strtold_l", sh_strtold_l),
        BIONIC_FUNCTION("fclose", sh_fclose),
        BIONIC_FUNCTION("feof", sh_feof),
        BIONIC_FUNCTION("ferror", sh_ferror),
        BIONIC_FUNCTION("fflush", sh_fflush),
        BIONIC_FUNCTION("fgetc", sh_fgetc),
        BIONIC_FUNCTION("fgets", sh_fgets),
        BIONIC_FUNCTION("fileno", sh_fileno),
        BIONIC_FUNCTION("fprintf", sh_fprintf),
        BIONIC_FUNCTION("vfprintf", sh_vfprintf),
        BIONIC_FUNCTION("fscanf", sh_fscanf),
        BIONIC_FUNCTION("fputc", sh_fputc),
        BIONIC_FUNCTION("fputs", sh_fputs),
        BIONIC_FUNCTION("fputwc", sh_fputwc),
        BIONIC_FUNCTION("fread", sh_fread),
        BIONIC_FUNCTION("fseek", sh_fseek),
        BIONIC_FUNCTION("fseeko", sh_fseeko),
        BIONIC_FUNCTION("ftell", sh_ftell),
        BIONIC_FUNCTION("ftello", sh_ftello),
        BIONIC_FUNCTION("fwrite", sh_fwrite),
        BIONIC_FUNCTION("getc", sh_getc),
        BIONIC_FUNCTION("getwc", sh_getwc),
        BIONIC_FUNCTION("getline", sh_getline),
        BIONIC_FUNCTION("clearerr", sh_clearerr),
        BIONIC_FUNCTION("putc", sh_putc),
        BIONIC_FUNCTION("rewind", sh_rewind),
        BIONIC_FUNCTION("setbuf", sh_setbuf),
        BIONIC_FUNCTION("ungetc", sh_ungetc),
        BIONIC_FUNCTION("ungetwc", sh_ungetwc),
        BIONIC_FUNCTION("pclose", sh_pclose),
    };
}

void* dyn::resolveBionicSymbol(std::string_view name, bool weak) {
    for (const auto& symbol : bionicSymbols) {
        if (name == symbol.name) {
            return symbol.address;
        }
    }
    if (auto* address = resolveGlibcSymbol(name, {}, true); address) {
        return address;
    }
    if (!weak) {
        fprintf(stderr, "bionic bridge: no ABI thunk for %.*s\n", static_cast<int>(name.size()), name.data());
    }

    return nullptr;
}
