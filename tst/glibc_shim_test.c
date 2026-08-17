/* Conformance battery for the glibc bridge: built against the real glibc,
 * loaded through SoLo, and every implemented adapter family is called with
 * its glibc ABI expectations checked. Returns the number of failed checks. */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <ftw.h>
#include <inttypes.h>
#include <langinfo.h>
#include <limits.h>
#include <link.h>
#include <locale.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/auxv.h>
#include <sys/pidfd.h>
#include <ttyent.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

static int failures;

static const char* temporary_directory(void) {
    const char* directory = getenv("TMPDIR");

    return directory && *directory ? directory : "/tmp";
}

#define CHECK(condition)                                                \
    do {                                                                \
        if (!(condition)) {                                             \
            ++failures;                                                 \
            fprintf(stderr, "shim check failed: %s (errno %d)\n", #condition, errno);     \
        }                                                               \
    } while (0)

/* The fortified entry points, called directly. */
extern char* __strcat_chk(char*, const char*, size_t);
extern char* __strcpy_chk(char*, const char*, size_t);
extern char* __strncpy_chk(char*, const char*, size_t, size_t);
extern char* __strncat_chk(char*, const char*, size_t, size_t);
extern char* __stpcpy_chk(char*, const char*, size_t);
extern size_t __strlcpy_chk(char*, const char*, size_t, size_t);
extern void* __memcpy_chk(void*, const void*, size_t, size_t);
extern void* __memmove_chk(void*, const void*, size_t, size_t);
extern void* __memset_chk(void*, int, size_t, size_t);
extern void* __mempcpy_chk(void*, const void*, size_t, size_t);
extern int __snprintf_chk(char*, size_t, int, size_t, const char*, ...);
extern int __sprintf_chk(char*, int, size_t, const char*, ...);
extern int __printf_chk(int, const char*, ...);
extern int __fprintf_chk(FILE*, int, const char*, ...);
extern int __asprintf_chk(char**, int, const char*, ...);
extern size_t __fread_chk(void*, size_t, size_t, size_t, FILE*);
extern char* __fgets_chk(char*, size_t, int, FILE*);
extern char* __getcwd_chk(char*, size_t, size_t);
extern int __getgroups_chk(int, gid_t*, size_t);
extern int __inet_pton_chk(int, const char*, void*, size_t);
extern int __poll_chk(struct pollfd*, nfds_t, int, size_t);
extern long __fdelt_chk(long);
extern ssize_t __read_chk(int, void*, size_t, size_t);
extern ssize_t __pread_chk(int, void*, size_t, off_t, size_t);
extern ssize_t __readlinkat_chk(int, const char*, char*, size_t, size_t);
extern char* __realpath_chk(const char*, char*, size_t);
extern void __explicit_bzero_chk(void*, size_t, size_t);
extern size_t __mbstowcs_chk(wchar_t*, const char*, size_t, size_t);
extern size_t __wcrtomb_chk(char*, wchar_t, mbstate_t*, size_t);
extern wchar_t* __wcsncpy_chk(wchar_t*, const wchar_t*, size_t, size_t);
extern wchar_t* __wmemcpy_chk(wchar_t*, const wchar_t*, size_t, size_t);
extern wchar_t* __wmemset_chk(wchar_t*, wchar_t, size_t, size_t);

extern int __isoc99_sscanf(const char*, const char*, ...);
extern long __isoc23_strtol(const char*, char**, int);
extern unsigned long __isoc23_strtoul(const char*, char**, int);
extern long long __isoc23_strtoll(const char*, char**, int);
extern unsigned long long __isoc23_strtoull(const char*, char**, int);
extern intmax_t __isoc23_strtoimax(const char*, char**, int);
extern uintmax_t __isoc23_strtoumax(const char*, char**, int);
extern long __isoc23_wcstol(const wchar_t*, wchar_t**, int);
extern int __isoc23_sscanf(const char*, const char*, ...);

extern int* __errno_location(void);
extern const unsigned short** __ctype_b_loc(void);
extern const int** __ctype_tolower_loc(void);
extern const int** __ctype_toupper_loc(void);
extern size_t __ctype_get_mb_cur_max(void);
extern long __sysconf(int);
extern int __sched_cpucount(size_t, const cpu_set_t*);
extern char* __xpg_basename(char*);
extern size_t __mbrlen(const char*, size_t, mbstate_t*);
extern void __longjmp_chk(jmp_buf, int);
extern size_t parse_printf_format(const char*, size_t, int*);
extern int __res_ninit(void*);
extern void __res_nclose(void*);
extern int getsgnam_r(const char*, void*, char*, size_t, void**);
extern const char* strerrorname_np(int);
extern int rpmatch(const char*);
extern void free_sized(void*, size_t);
extern void free_aligned_sized(void*, size_t, size_t);
extern int close_range(unsigned, unsigned, int);
extern int fsopen(const char*, unsigned);
extern struct mallinfo2 mallinfo2(void);
extern int malloc_trim(size_t);

static void strings(void) {
    char buffer[64];

    CHECK(bcmp("abc", "abc", 3) == 0);
    CHECK(strcmp(__strcat_chk(strcpy(buffer, "ab"), "cd", sizeof(buffer)), "abcd") == 0);
    CHECK(strcmp(__strcpy_chk(buffer, "hello", sizeof(buffer)), "hello") == 0);
    CHECK(__stpcpy_chk(buffer, "hey", sizeof(buffer)) == buffer + 3);
    CHECK(strcmp(stpcpy(buffer, "jump"), "") == 0 && buffer[0] == 'j');
    __strncpy_chk(buffer, "abcdef", 6, sizeof(buffer));
    buffer[6] = 0;
    CHECK(strcmp(buffer, "abcdef") == 0);
    buffer[2] = 0;
    __strncat_chk(buffer, "ZW", 2, sizeof(buffer));
    CHECK(strcmp(buffer, "abZW") == 0);
    CHECK(__strlcpy_chk(buffer, "tiny", sizeof(buffer), sizeof(buffer)) == 4);
    CHECK(strcmp((char*)__memcpy_chk(buffer, "xyz", 4, sizeof(buffer)), "xyz") == 0);
    CHECK(strcmp((char*)__memmove_chk(buffer + 1, buffer, 3, sizeof(buffer) - 1) - 1, "xxyz") == 0);
    __memset_chk(buffer, 'k', 3, sizeof(buffer));
    CHECK(strncmp(buffer, "kkk", 3) == 0);
    CHECK(__mempcpy_chk(buffer, "qq", 2, sizeof(buffer)) == buffer + 2);
    CHECK(strchr("finder", 'd') != NULL);
    CHECK(strrchr("finder", 'e') != NULL);
    CHECK(strstr("haystackneedle", "needle") != NULL);
    CHECK(strchrnul("abc", 'z')[0] == 0);
    CHECK(*(char*)rawmemchr("abcz", 'z') == 'z');
    CHECK(memrchr("aXbX", 'X', 4) != NULL);
    CHECK(strncmp("alpha", "alps", 3) == 0);
    strcpy(buffer, "one,two");
    char* state = NULL;
    CHECK(strcmp(strtok_r(buffer, ",", &state), "one") == 0);
    CHECK(strcmp(strtok_r(NULL, ",", &state), "two") == 0);
    CHECK(strerror(2) != NULL);
    char errbuf[64];
    CHECK(strerror_r(2, errbuf, sizeof(errbuf)) != NULL);
    strcpy(buffer, "/usr/lib/libx.so");
    CHECK(strcmp(__xpg_basename(buffer), "libx.so") == 0);
    __explicit_bzero_chk(buffer, 4, sizeof(buffer));
    CHECK(buffer[0] == 0 && buffer[3] == 0);
    strerrorname_np(22);
}

static void formatting(void) {
    char buffer[128];
    char* allocated = NULL;

    CHECK(__snprintf_chk(buffer, sizeof(buffer), 1, sizeof(buffer), "%d-%s", 42, "ok") == 5);
    CHECK(strcmp(buffer, "42-ok") == 0);
    CHECK(__sprintf_chk(buffer, 1, sizeof(buffer), "%x", 255) == 2);
    CHECK(strcmp(buffer, "ff") == 0);
    CHECK(snprintf(buffer, sizeof(buffer), "%.2f", 2.5) == 4);
    CHECK(strcmp(buffer, "2.50") == 0);
    CHECK(__asprintf_chk(&allocated, 1, "n=%d", 7) == 3);
    CHECK(allocated && strcmp(allocated, "n=7") == 0);
    free(allocated);

    int types[8] = {0};
    CHECK(parse_printf_format("%d %s %f %*d %lld", 8, types) == 6);
    CHECK(types[0] == 0 /* PA_INT */);
    CHECK(types[1] == 3 /* PA_STRING */);
    CHECK(types[2] == 7 /* PA_DOUBLE */);
    CHECK(types[3] == 0 /* the width argument */);
    CHECK(types[4] == 0 /* the value behind the width */);
    CHECK(types[5] == (0 | 0x100) /* PA_INT | PA_FLAG_LONG_LONG */);
}

static void numbers(void) {
    char* end = NULL;

    CHECK(__isoc23_strtol("0x2a", &end, 0) == 42);
    CHECK(__isoc23_strtoul("101", &end, 2) == 5);
    CHECK(__isoc23_strtoll("-9000000000", &end, 10) == -9000000000LL);
    CHECK(__isoc23_strtoull("18446744073709551615", &end, 10) == 18446744073709551615ULL);
    CHECK(__isoc23_strtoimax("-77", &end, 10) == -77);
    CHECK(__isoc23_strtoumax("77", &end, 10) == 77);
    CHECK(strtod("2.75", &end) == 2.75);
    wchar_t* wend = NULL;
    CHECK(__isoc23_wcstol(L"52", &wend, 10) == 52);

    int a = 0;
    int b = 0;
    CHECK(__isoc99_sscanf("3 4", "%d %d", &a, &b) == 2 && a == 3 && b == 4);
    CHECK(__isoc23_sscanf("5 six", "%d %s", &a, (char[8]){0}) == 2 && a == 5);
}

static void stdio_files(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/solo-shim-XXXXXX", temporary_directory());
    int descriptor = mkstemp64(path);

    CHECK(descriptor >= 0);
    CHECK(write(descriptor, "line one\nline two\n", 18) == 18);

    FILE* stream = fopen64(path, "r");
    CHECK(stream != NULL);
    if (!stream) {
        return;
    }
    char buffer[64];
    CHECK(__fgets_chk(buffer, sizeof(buffer), sizeof(buffer), stream) != NULL);
    CHECK(strcmp(buffer, "line one\n") == 0);
    char* line = NULL;
    size_t capacity = 0;
    extern ssize_t __getdelim(char**, size_t*, int, FILE*);
    CHECK(__getdelim(&line, &capacity, '\n', stream) == 9);
    CHECK(line && strcmp(line, "line two\n") == 0);
    free(line);
    CHECK(fseeko64(stream, 5, SEEK_SET) == 0);
    CHECK(ftello64(stream) == 5);
    CHECK(fseeko(stream, 0, SEEK_SET) == 0);
    CHECK(ftello(stream) == 0);
    CHECK(__fread_chk(buffer, sizeof(buffer), 1, 4, stream) == 4);
    CHECK(fileno(stream) >= 0);
    FILE* reopened = freopen64(path, "r", stream);
    CHECK(reopened != NULL);
    CHECK(fscanf(reopened, "%*s") == 0);
    CHECK(fclose(reopened) == 0);

    FILE* writable = fdopen(open64(path, O_WRONLY), "w");
    CHECK(writable != NULL);
    if (!writable) {
        return;
    }
    CHECK(fputs("x", writable) >= 0);
    CHECK(fputc('y', writable) == 'y');
    CHECK(__fprintf_chk(writable, 1, "%d", 9) == 1);
    CHECK(fclose(writable) == 0);

    struct stat64 status;
    struct stat plain_status;
    CHECK(stat64(path, &status) == 0 && status.st_size > 0);
    CHECK(lstat64(path, &status) == 0);
    descriptor = open64(path, O_RDONLY);
    CHECK(descriptor >= 0);
    CHECK(fstat64(descriptor, &status) == 0);
    CHECK(fstat(descriptor, &plain_status) == 0);
    CHECK(fstatat64(AT_FDCWD, path, &status, 0) == 0);
    CHECK(statx(AT_FDCWD, path, 0, 0x7ff, &(struct statx){0}) == 0);
    CHECK(lseek64(descriptor, 1, SEEK_SET) == 1);
    CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
    CHECK(__pread_chk(descriptor, buffer, 4, 0, sizeof(buffer)) == 4);
    CHECK(pread64(descriptor, buffer, 4, 0) == 4);
    CHECK(__read_chk(descriptor, buffer, 2, sizeof(buffer)) == 2);
    CHECK(fcntl64(descriptor, F_GETFL) >= 0);
    close(descriptor);

    descriptor = open64(path, O_WRONLY);
    CHECK(pwrite64(descriptor, "zz", 2, 0) == 2);
    CHECK(ftruncate64(descriptor, 8) == 0);
    CHECK(posix_fallocate64(descriptor, 0, 16) == 0);
    CHECK(posix_fadvise64(descriptor, 0, 0, POSIX_FADV_NORMAL) == 0);
    close(descriptor);

    struct statfs fs_status;
    struct statfs64 fs_status64;
    CHECK(statfs(temporary_directory(), &fs_status) == 0);
    CHECK(statfs64(temporary_directory(), &fs_status64) == 0);
    struct statvfs64 vfs_status;
    CHECK(statvfs64(temporary_directory(), &vfs_status) == 0);
    descriptor = open64(temporary_directory(), O_RDONLY);
    CHECK(fstatfs(descriptor, &fs_status) == 0);
    CHECK(fstatfs64(descriptor, &fs_status64) == 0);
    CHECK(fstatvfs64(descriptor, &vfs_status) == 0);
    close(descriptor);

    CHECK(access(path, R_OK) == 0);
    char resolved[PATH_MAX];
    CHECK(__realpath_chk(path, resolved, sizeof(resolved)) != NULL);
    CHECK(realpath(path, resolved) != NULL);
    CHECK(readlink("/proc/self/exe", buffer, sizeof(buffer)) > 0);
    CHECK(__readlinkat_chk(AT_FDCWD, "/proc/self/exe", buffer, sizeof(buffer), sizeof(buffer)) > 0);
    CHECK(__getcwd_chk(resolved, sizeof(resolved), sizeof(resolved)) != NULL);
    CHECK(unlink(path) == 0);

    snprintf(path, sizeof(path), "%s/solo-shim-XXXXXX", temporary_directory());
    descriptor = mkostemp64(path, O_CLOEXEC);
    CHECK(descriptor >= 0);
    close(descriptor);
    unlink(path);
    snprintf(path, sizeof(path), "%s/solo-shim-XXXXXX.txt", temporary_directory());
    descriptor = mkstemps64(path, 4);
    CHECK(descriptor >= 0);
    close(descriptor);
    unlink(path);
    snprintf(path, sizeof(path), "%s/solo-shim-creat", temporary_directory());
    descriptor = creat64(path, 0600);
    CHECK(descriptor >= 0);
    close(descriptor);
    unlink(path);
}

static void memory(void) {
    void* block = malloc(32);

    CHECK(block != NULL);
    CHECK(malloc_usable_size(block) >= 32);
    block = realloc(block, 64);
    CHECK(block != NULL);
    free(block);
    CHECK((block = calloc(4, 8)) != NULL);
    free_sized(block, 32);
    CHECK(posix_memalign(&block, 64, 128) == 0 && ((uintptr_t)block % 64) == 0);
    free_aligned_sized(block, 64, 128);
    void* array = reallocarray(NULL, 4, 4);
    CHECK(array != NULL);
    free(array);
    CHECK(malloc_trim(0) == 0);
    mallinfo2();

    void* mapping = mmap64(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(mprotect(mapping, 4096, PROT_READ) == 0);
    void* grown = mremap(mapping, 8192, 16384, MREMAP_MAYMOVE);
    /* some hardened kernels reject mremap; the bridge must still relay */
    CHECK(grown != MAP_FAILED || errno == EFAULT || errno == ENOMEM);
    if (grown != MAP_FAILED) {
        mapping = grown;
        munmap(mapping, 16384);
    } else {
        munmap(mapping, 8192);
    }
}

static int directoryFilter(const struct dirent* entry) {
    return entry->d_name[0] != '.';
}

static int directoryFilter64(const struct dirent64* entry) {
    return entry->d_name[0] != '.';
}

static void directories(void) {
    DIR* directory = opendir("/proc/self");

    CHECK(directory != NULL);
    CHECK(readdir(directory) != NULL);
    CHECK(readdir64(directory) != NULL);
    CHECK(closedir(directory) == 0);

    struct dirent64** entries = NULL;
    int count = scandir64("/proc/self", &entries, directoryFilter64, alphasort64);
    CHECK(count > 0);
    while (count > 0) {
        free(entries[--count]);
    }
    free(entries);

    entries = NULL;
    count = scandir64("/proc/self", &entries, directoryFilter64, versionsort64);
    CHECK(count > 0);
    while (count > 0) {
        free(entries[--count]);
    }
    free(entries);

    struct dirent** plain = NULL;
    int descriptor = open64("/proc", O_RDONLY | O_DIRECTORY);
    count = scandirat(descriptor, "self", &plain, directoryFilter, alphasort);
    CHECK(count > 0);
    while (count > 0) {
        free(plain[--count]);
    }
    free(plain);
    close(descriptor);
}

static int nftwSeenFile;
static int nftwSeenDirectory;

static int nftwVisitor(const char* path, const struct stat* status, int type, struct FTW* info) {
    (void)path;
    (void)status;
    (void)info;
    /* glibc type codes, translated by the bridge from musl's */
    if (type == FTW_F) {
        ++nftwSeenFile;
    }
    if (type == FTW_D || type == FTW_DP) {
        ++nftwSeenDirectory;
    }
    return 0;
}

static void walks(void) {
    char path[256];

    snprintf(path, sizeof(path), "%s/solo-nftw-XXXXXX", temporary_directory());
    CHECK(mkdtemp(path) != NULL);
    char inner[320];
    snprintf(inner, sizeof(inner), "%s/file", path);
    int descriptor = creat64(inner, 0600);
    CHECK(descriptor >= 0);
    close(descriptor);

    CHECK(nftw(path, nftwVisitor, 8, FTW_PHYS) == 0);
    CHECK(nftwSeenFile == 1);
    CHECK(nftwSeenDirectory == 1);
    unlink(inner);
    rmdir(path);
}

static int ftsCompare(const FTSENT** left, const FTSENT** right) {
    return strcmp((*left)->fts_name, (*right)->fts_name);
}

static void treeWalks(void) {
    char path[256];

    snprintf(path, sizeof(path), "%s/solo-fts-XXXXXX", temporary_directory());
    CHECK(mkdtemp(path) != NULL);
    char file[320], sub[320], subfile[384];
    snprintf(file, sizeof(file), "%s/alpha", path);
    snprintf(sub, sizeof(sub), "%s/sub", path);
    snprintf(subfile, sizeof(subfile), "%s/sub/beta", path);
    int descriptor = creat64(file, 0600);
    CHECK(descriptor >= 0);
    close(descriptor);
    CHECK(mkdir(sub, 0700) == 0);
    descriptor = creat64(subfile, 0600);
    CHECK(descriptor >= 0);
    close(descriptor);

    /* Pre-order parent, sorted children, post-order after the subtree. */
    char* const roots[] = {path, NULL};
    FTS* walk = fts_open(roots, FTS_PHYSICAL | FTS_NOCHDIR, ftsCompare);
    CHECK(walk != NULL);
    FTSENT* entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_D && strcmp(entry->fts_path, path) == 0);
    CHECK(entry && entry->fts_level == 0);
    entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_F && strcmp(entry->fts_name, "alpha") == 0);
    CHECK(entry && entry->fts_level == 1 && entry->fts_statp->st_size == 0);
    CHECK(entry && strcmp(entry->fts_accpath, file) == 0);
    entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_D && strcmp(entry->fts_name, "sub") == 0);
    entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_F && strcmp(entry->fts_name, "beta") == 0);
    CHECK(entry && entry->fts_parent && strcmp(entry->fts_parent->fts_name, "sub") == 0);
    entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_DP && strcmp(entry->fts_name, "sub") == 0);
    entry = fts_read(walk);
    CHECK(entry && entry->fts_info == FTS_DP && entry->fts_level == 0);
    CHECK(fts_read(walk) == NULL);
    CHECK(fts_close(walk) == 0);

    /* FTS_SKIP prunes the subtree but still delivers the post-order visit. */
    walk = fts_open(roots, FTS_PHYSICAL | FTS_NOCHDIR, ftsCompare);
    CHECK(walk != NULL);
    int sawBeta = 0, sawSubPost = 0;
    while ((entry = fts_read(walk)) != NULL) {
        if (strcmp(entry->fts_name, "beta") == 0) {
            sawBeta = 1;
        }
        if (strcmp(entry->fts_name, "sub") == 0 && entry->fts_info == FTS_D) {
            CHECK(fts_set(walk, entry, FTS_SKIP) == 0);
        }
        if (strcmp(entry->fts_name, "sub") == 0 && entry->fts_info == FTS_DP) {
            sawSubPost = 1;
        }
    }
    CHECK(!sawBeta && sawSubPost);
    CHECK(fts_close(walk) == 0);

    unlink(subfile);
    rmdir(sub);
    unlink(file);
    rmdir(path);
}

static void processors(void) {
    cpu_set_t* set = CPU_ALLOC(130);
    size_t size = CPU_ALLOC_SIZE(130);
    CHECK(set != NULL);
    CHECK(size == 24);
    CPU_ZERO_S(size, set);
    CPU_SET_S(129, size, set);
    CHECK(CPU_ISSET_S(129, size, set));
    CHECK(!CPU_ISSET_S(1, size, set));
    CPU_FREE(set);

    int pidfd = pidfd_open(getpid(), 0);
    CHECK(pidfd >= 0 || errno == ENOSYS);
    if (pidfd >= 0) {
        close(pidfd);
    }

    /* Linux systems do not ship /etc/ttys, so every lookup fails. */
    if (access("/etc/ttys", F_OK) != 0) {
        CHECK(getttynam("console") == NULL);
    }
}

static void expressions(void) {
    regex_t compiled;
    regmatch_t matches[2];

    CHECK(regcomp(&compiled, "a(b+)c", REG_EXTENDED) == 0);
    CHECK(compiled.re_nsub == 1);
    CHECK(regexec(&compiled, "xxabbbcyy", 2, matches, 0) == 0);
    CHECK(matches[0].rm_so == 2 && matches[0].rm_eo == 7);
    CHECK(matches[1].rm_so == 3 && matches[1].rm_eo == 6);
    CHECK(regexec(&compiled, "nothing", 2, matches, 0) == REG_NOMATCH);
    char message[64];
    CHECK(regerror(REG_NOMATCH, &compiled, message, sizeof(message)) > 0);
    regfree(&compiled);
}

static void descriptorsAndLimits(void) {
    CHECK(__fdelt_chk(65) == 1);

    struct pollfd poller = {.fd = 0, .events = POLLIN};
    CHECK(__poll_chk(&poller, 1, 0, sizeof(poller)) >= 0);

    unsigned char address[16];
    CHECK(__inet_pton_chk(AF_INET, "127.0.0.1", address, sizeof(address)) == 1);
    CHECK(address[0] == 127 && address[3] == 1);

    gid_t groups[64];
    CHECK(__getgroups_chk(64, groups, sizeof(groups)) >= 0);

    struct rlimit64 limit;
    CHECK(getrlimit64(RLIMIT_NOFILE, &limit) == 0);
    CHECK(setrlimit64(RLIMIT_NOFILE, &limit) == 0);

    int low = open64("/dev/null", O_RDONLY);
    int high = fcntl64(low, F_DUPFD, 900);
    CHECK(high >= 900);
    CHECK(close_range(900, 950, 0) == 0);
    CHECK(fcntl64(high, F_GETFD) == -1 && errno == EBADF);
    close(low);

    /* The new mount API answers through the bridge; CI may run privileged. */
    int filesystem = fsopen("tmpfs", 0);
    CHECK(filesystem >= 0 || errno == EPERM || errno == ENOSYS);
    if (filesystem >= 0) {
        close(filesystem);
    }

    CHECK(__res_ninit(NULL) == 0);
    __res_nclose(NULL);
    void* record = NULL;
    char sgbuffer[64];
    CHECK(getsgnam_r("nosuchgroup", NULL, sgbuffer, sizeof(sgbuffer), &record) == 0 && record == NULL);
    CHECK(rpmatch("yes") == 1 && rpmatch("NO") == 0 && rpmatch("?") == -1);
}

static void localesAndWide(void) {
    locale_t base = newlocale(LC_ALL_MASK, "C", (locale_t)0);

    CHECK(base != (locale_t)0);
    locale_t copy = duplocale(base);
    CHECK(copy != (locale_t)0);
    locale_t previous = uselocale(copy);
    CHECK(uselocale(previous ? previous : LC_GLOBAL_LOCALE) != (locale_t)0);
    CHECK(nl_langinfo(CODESET) != NULL);
    CHECK(nl_langinfo_l(CODESET, base) != NULL);
    CHECK(iswctype_l(L'7', wctype_l("digit", base), base));
    CHECK(towlower_l(L'A', base) == L'a');
    CHECK(towupper_l(L'a', base) == L'A');
    CHECK(towctrans_l(L'a', wctrans_l("toupper", base), base) == L'A');
    freelocale(copy);
    freelocale(base);

    CHECK(btowc('a') == L'a');
    CHECK(wctob(L'a') == 'a');
    CHECK(__ctype_get_mb_cur_max() >= 1);
    CHECK(((*__ctype_b_loc())['7'] & _ISdigit) != 0);
    CHECK((*__ctype_tolower_loc())['A'] == 'a');
    CHECK((*__ctype_toupper_loc())['a'] == 'A');

    mbstate_t state = {0};
    CHECK(__mbrlen("a", 1, &state) == 1);
    wchar_t wide[8];
    CHECK(__mbstowcs_chk(wide, "ab", 8, sizeof(wide) / sizeof(wchar_t)) == 2);
    char narrow[MB_LEN_MAX];
    memset(&state, 0, sizeof(state));
    CHECK(__wcrtomb_chk(narrow, L'x', &state, sizeof(narrow)) == 1);
    wchar_t more[8];
    CHECK(__wcsncpy_chk(more, L"wc", 3, 8) == more);
    CHECK(__wmemcpy_chk(more, L"zz", 2, 8) == more);
    CHECK(__wmemset_chk(more, L'q', 2, 8) == more);

    extern float __strtof_l(const char*, char**, locale_t);
    extern double __strtod_l(const char*, char**, locale_t);
    extern int __strcoll_l(const char*, const char*, locale_t);
    extern size_t __strxfrm_l(char*, const char*, size_t, locale_t);
    extern int __wcscoll_l(const wchar_t*, const wchar_t*, locale_t);
    extern size_t __wcsxfrm_l(wchar_t*, const wchar_t*, size_t, locale_t);
    extern size_t __strftime_l(char*, size_t, const char*, const struct tm*, locale_t);
    locale_t plain = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    char* tail = NULL;
    CHECK(__strtof_l("1.5", &tail, plain) == 1.5f);
    CHECK(__strtod_l("2.5", &tail, plain) == 2.5);
    CHECK(__strcoll_l("a", "b", plain) < 0);
    char transformed[16];
    CHECK(__strxfrm_l(transformed, "abc", sizeof(transformed), plain) > 0);
    CHECK(__wcscoll_l(L"a", L"b", plain) < 0);
    wchar_t wtransformed[16];
    __wcsxfrm_l(wtransformed, L"abc", 16, plain);
    struct tm moment = {.tm_year = 100, .tm_mon = 1, .tm_mday = 2};
    char formatted[32];
    CHECK(__strftime_l(formatted, sizeof(formatted), "%Y", &moment, plain) == 4);
    CHECK(strcmp(formatted, "2000") == 0);
    freelocale(plain);
}

static void timeKeeping(void) {
    tzset();
    CHECK(tzname[0] != NULL);

    time_t moment = 86400;
    struct tm decomposed;
    CHECK(gmtime_r(&moment, &decomposed) != NULL && decomposed.tm_mday == 2);
    CHECK(localtime_r(&moment, &decomposed) != NULL);

    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000};
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &delay, NULL) == 0);
}

static int compareIntegers(const void* left, const void* right) {
    return *(const int*)left - *(const int*)right;
}

static int compareWithContext(const void* left, const void* right, void* context) {
    ++*(int*)context;
    return *(const int*)left - *(const int*)right;
}

static void sorting(void) {
    int values[] = {3, 1, 2};

    qsort(values, 3, sizeof(int), compareIntegers);
    CHECK(values[0] == 1 && values[2] == 3);

    int context = 0;
    int more[] = {5, 4};
    qsort_r(more, 2, sizeof(int), compareWithContext, &context);
    CHECK(more[0] == 4 && context > 0);
}

static void processAndSystem(void) {
    CHECK(getenv("PATH") != NULL);
    secure_getenv("PATH");
    CHECK(getauxval(AT_PAGESZ) >= 4096);
    CHECK(sysconf(_SC_PAGESIZE) >= 4096);
    CHECK(__sysconf(_SC_PAGESIZE) >= 4096);

    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    CPU_SET(3, &cpus);
    CHECK(__sched_cpucount(sizeof(cpus), &cpus) == 2);

    unsigned char noise[16] = {0};
    arc4random_buf(noise, sizeof(noise));
    arc4random();
    (void)noise;

    extern char** environ;
    CHECK(environ != NULL && environ[0] != NULL);
    extern char* program_invocation_name;
    CHECK(program_invocation_name != NULL);
    extern char* program_invocation_short_name;
    CHECK(program_invocation_short_name != NULL);

    errno = 0;
    CHECK(__errno_location() == &errno);

    struct sigaction action;
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0);

    extern int __register_atfork(void (*)(void), void (*)(void), void (*)(void), void*);
    CHECK(__register_atfork(NULL, NULL, NULL, NULL) == 0);
}

extern char _IO_2_1_stdin_[];
extern char _IO_2_1_stdout_[];
extern char _IO_2_1_stderr_[];
extern int __overflow(FILE*, int);
extern int __uflow(FILE*);

static void inlinedStdio(void) {
    /* The old ABI: code compiled against ancient glibc headers references the
       _IO_2_1_* objects instead of the stdin/stdout/stderr pointers. */
    CHECK((FILE*)_IO_2_1_stdin_ == stdin);
    CHECK((FILE*)_IO_2_1_stdout_ == stdout);
    CHECK((FILE*)_IO_2_1_stderr_ == stderr);

    char path[256];
    snprintf(path, sizeof(path), "%s/solo-inline-XXXXXX", temporary_directory());
    int descriptor = mkstemp64(path);
    CHECK(descriptor >= 0);
    close(descriptor);

    /* What -O2 compiles putc_unlocked into: poke the glibc _IO_FILE fields,
       fall back to __overflow. musl lays its FILE out to make this work. */
    FILE* out = fopen64(path, "w");
    CHECK(out != NULL);
    if (out) {
        struct GlibcIoFile {
            int flags;
            char* read_ptr;
            char* read_end;
            char* read_base;
            char* write_base;
            char* write_ptr;
            char* write_end;
        }* raw = (struct GlibcIoFile*)out;
        int result = raw->write_ptr >= raw->write_end ? __overflow(out, 'Q') : (*raw->write_ptr++ = 'Q');
        CHECK(result == 'Q');
        CHECK(putc_unlocked('R', out) == 'R');
        CHECK(fputc_unlocked('S', out) == 'S');
        CHECK(fclose(out) == 0);
    }

    FILE* in = fopen64(path, "r");
    CHECK(in != NULL);
    if (in) {
        struct GlibcIoFile {
            int flags;
            char* read_ptr;
            char* read_end;
        }* raw = (struct GlibcIoFile*)in;
        int first = raw->read_ptr < raw->read_end ? *raw->read_ptr++ : __uflow(in);
        CHECK(first == 'Q');
        CHECK(getc_unlocked(in) == 'R');
        CHECK(fgetc_unlocked(in) == 'S');
        /* the inlined feof_unlocked reads the glibc flag bit */
        CHECK(getc_unlocked(in) == EOF);
        CHECK((raw->flags & 0x10) != 0);
        CHECK(feof_unlocked(in) != 0);
        CHECK(fclose(in) == 0);
    }
    unlink(path);
}

static void jumps(void) {
    jmp_buf state;
    volatile int reached = 0;
    int value;

    if ((value = _setjmp(state)) == 0) {
        __longjmp_chk(state, 7);
    } else {
        reached = value;
    }
    CHECK(reached == 7);
}

static void schedulingBridge(void) {
    int policy = 0;
    struct sched_param parameters = {.sched_priority = -1};

    CHECK(pthread_getschedparam(pthread_self(), &policy, &parameters) == 0);
    CHECK(parameters.sched_priority == 0);

    pthread_attr_t attributes;
    CHECK(pthread_attr_init(&attributes) == 0);
    parameters.sched_priority = 0;
    CHECK(pthread_attr_setschedparam(&attributes, &parameters) == 0);
    parameters.sched_priority = -1;
    CHECK(pthread_attr_getschedparam(&attributes, &parameters) == 0);
    CHECK(parameters.sched_priority == 0);
    CHECK(pthread_attr_destroy(&attributes) == 0);
}

static int countPhdrs(struct dl_phdr_info* info, size_t size, void* data) {
    (void)info;
    (void)size;
    ++*(int*)data;
    return 0;
}

static void dynamicLinking(void) {
    void* handle = dlopen(NULL, RTLD_LAZY);

    CHECK(handle != NULL);
    CHECK(dlsym(handle, "strlen") != NULL);

    void* self = dlopen("libdlfcn-test-shim.so", RTLD_LAZY);
    CHECK(self != NULL);
    CHECK(dlsym(self, "glibc_shim_test") != NULL);
    CHECK(dlvsym(self, "glibc_shim_test", "NOSUCHVERSION") == NULL);
    dlerror();

    /* the handle is a link_map facade */
    struct link_map* map = (struct link_map*)self;
    CHECK(map->l_addr != 0);
    CHECK(map->l_name != NULL && strstr(map->l_name, "libdlfcn-test-shim.so") != NULL);
    CHECK(map->l_ld != NULL);

    struct link_map* queried = NULL;
    CHECK(dlinfo(self, RTLD_DI_LINKMAP, &queried) == 0);
    CHECK(queried == map);

    Dl_info symbol_info;
    int glibc_shim_test(void);
    CHECK(dladdr((void*)&glibc_shim_test, &symbol_info) != 0);
    CHECK(symbol_info.dli_fname != NULL);
    CHECK(symbol_info.dli_sname && strcmp(symbol_info.dli_sname, "glibc_shim_test") == 0);

    int images = 0;
    CHECK(dl_iterate_phdr(countPhdrs, &images) == 0);
    CHECK(images >= 2);

    CHECK(dlclose(self) == 0);
}

int glibc_shim_test(void) {
    failures = 0;

    strings();
    formatting();
    numbers();
    stdio_files();
    memory();
    directories();
    walks();
    treeWalks();
    processors();
    expressions();
    descriptorsAndLimits();
    localesAndWide();
    timeKeeping();
    sorting();
    processAndSystem();
    inlinedStdio();
    jumps();
    schedulingBridge();
    dynamicLinking();

    return failures;
}
