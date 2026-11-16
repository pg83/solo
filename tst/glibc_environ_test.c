#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Compile separately for every public spelling: a COPY relocation may name
 * any one of them, and the bridge must find the same guest-owned pointer. */
#ifndef GUEST_ENVIRON
#define GUEST_ENVIRON environ
#endif
extern char** GUEST_ENVIRON;

#if defined(__x86_64__)
extern char* old_secure_getenv(const char*);
__asm__(".symver old_secure_getenv, __secure_getenv@GLIBC_2.2.5");
#endif

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "environ check failed at %d: %s (errno=%d)\n", __LINE__, #condition, errno); \
        return 1; \
    } \
} while (0)

static const char* table_value(char* const table[], const char* name) {
    size_t length = strlen(name);
    for (char* const* entry = table; entry && *entry; ++entry) {
        if (!strncmp(*entry, name, length) && (*entry)[length] == '=') {
            return *entry + length + 1;
        }
    }
    return NULL;
}

static int equal(const char* value, const char* expected) {
    return value && !strcmp(value, expected);
}

/* The parser must read the guest's COPY-relocated environ pointer, and keep
 * its ordering mode until optind=0 requests a full reinitialization. */
static int check_getopt(void) {
    char** original = GUEST_ENVIRON;
    char* posix[] = {"POSIXLY_CORRECT=1", NULL};
    char* empty[] = {NULL};
    char* args[] = {"prog", "file", "-a", NULL};
    const struct option longs[] = {{"alpha", no_argument, NULL, 'a'}, {NULL, 0, NULL, 0}};

    GUEST_ENVIRON = posix;
    optind = 0;
    opterr = 0;
    CHECK(getopt(3, args, "a") == -1 && optind == 1);
    CHECK(!strcmp(args[1], "file") && args[3] == NULL);
    optind = 0;
    CHECK(getopt_long(3, args, "a", longs, NULL) == -1 && optind == 1);
    optind = 0;
    CHECK(getopt_long_only(3, args, "a", longs, NULL) == -1 && optind == 1);

    GUEST_ENVIRON = empty;
    optind = 1;
    CHECK(getopt(3, args, "a") == -1 && optind == 1);
    optind = 0;
    CHECK(getopt(3, args, "a") == 'a' && optind == 3);
    CHECK(getopt(3, args, "a") == -1 && optind == 2);
    CHECK(!strcmp(args[1], "-a") && !strcmp(args[2], "file") && args[3] == NULL);

    GUEST_ENVIRON = original;
    optind = 0;
    opterr = 1;
    return 0;
}

static pthread_barrier_t readers_ready;

static void* read_environment(void* ignored) {
    (void)ignored;
    pthread_barrier_wait(&readers_ready);
    for (int count = 0; count < 1000; ++count) {
        if (!equal(secure_getenv("SOLO_GUEST_ENV"), "repointed") || !equal(getenv("SOLO_GUEST_ENV"), "repointed")) {
            return (void*)1;
        }
#if defined(__x86_64__)
        if (!equal(old_secure_getenv("SOLO_GUEST_ENV"), "repointed")) {
            return (void*)1;
        }
#endif
    }
    return NULL;
}

static int check_readers(void) {
    pthread_t readers[4];
    CHECK(!pthread_barrier_init(&readers_ready, NULL, 4));
    for (int index = 0; index < 4; ++index) {
        CHECK(!pthread_create(&readers[index], NULL, read_environment, NULL));
    }
    for (int index = 0; index < 4; ++index) {
        void* result;
        CHECK(!pthread_join(readers[index], &result));
        CHECK(result == NULL);
    }
    CHECK(!pthread_barrier_destroy(&readers_ready));
    CHECK(getenv("") == NULL && getenv("SOLO_GUEST_ENV=") == NULL);
    CHECK(getenv("SOLO_GUEST") == NULL && getenv("MISSING_VARIABLE") == NULL);
    return 0;
}

static int check_mutators(void) {
    CHECK(!setenv("SOLO_GUEST_ENV", "ignored", 0));
    CHECK(equal(table_value(GUEST_ENVIRON, "SOLO_GUEST_ENV"), "repointed"));
    CHECK(!setenv("SOLO_GUEST_ENV", "changed", 1));
    CHECK(equal(table_value(GUEST_ENVIRON, "SOLO_GUEST_ENV"), "changed"));
    /* Growing the table forces musl to publish its new pointer to the guest. */
    CHECK(!setenv("ADDED_VARIABLE", "added", 1));
    CHECK(equal(table_value(GUEST_ENVIRON, "ADDED_VARIABLE"), "added"));
    CHECK(equal(secure_getenv("ADDED_VARIABLE"), "added"));
    char** before = GUEST_ENVIRON;
    errno = 0;
    CHECK(setenv("bad=name", "value", 1) == -1 && errno == EINVAL);
    CHECK(GUEST_ENVIRON == before);

    char supplied[] = "PUT_VARIABLE=before";
    CHECK(!putenv(supplied));
    memcpy(strchr(supplied, '=') + 1, "after", sizeof("after"));
    CHECK(equal(getenv("PUT_VARIABLE"), "after"));
    CHECK(equal(table_value(GUEST_ENVIRON, "PUT_VARIABLE"), "after"));
    CHECK(!unsetenv("PUT_VARIABLE") && getenv("PUT_VARIABLE") == NULL);
    CHECK(!unsetenv("ADDED_VARIABLE"));
    CHECK(table_value(GUEST_ENVIRON, "ADDED_VARIABLE") == NULL);

    CHECK(!clearenv() && GUEST_ENVIRON == NULL);
    CHECK(getenv("SOLO_GUEST_ENV") == NULL);
    CHECK(!setenv("AFTER_CLEAR", "fresh", 1));
    CHECK(equal(table_value(GUEST_ENVIRON, "AFTER_CLEAR"), "fresh"));
    CHECK(!clearenv() && GUEST_ENVIRON == NULL);
    return 0;
}

static int check_exec(const char* executable, char* search_path) {
    const char* basename = strrchr(executable, '/');
    CHECK(basename != NULL);
    ++basename;
    for (int variant = 0; variant < 5; ++variant) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            /* Repoint afresh in each child. A preceding wrapped getenv or
             * execvp must not accidentally synchronize an unwrapped call. */
            char* inherited[] = {"SOLO_GUEST_ENV=child", search_path, NULL};
            char* explicit[] = {"SOLO_GUEST_ENV=explicit", "PATH=/no/such/path", NULL};
            GUEST_ENVIRON = inherited;
            char* args[] = {(char*)executable, "--child", variant == 4 ? "explicit" : "child", NULL};
            switch (variant) {
                case 0: {
                    execv(executable, args);
                    break;
                }
                case 1: {
                    execl(executable, executable, "--child", "child", (char*)NULL);
                    break;
                }
                case 2: {
                    execvp(basename, args);
                    break;
                }
                case 3: {
                    execlp(basename, executable, "--child", "child", (char*)NULL);
                    break;
                }
                case 4: {
                    execvpe(basename, args, explicit);
                    break;
                }
            }
            _exit(127);
        }
        int status;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
            fprintf(stderr, "environment exec variant %d failed\n", variant);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char** argv, char** envp) {
    if (argc == 3 && !strcmp(argv[1], "--child")) {
        /* Inspect the kernel-provided table, not a libc function which could
         * hide a bad exec environment by synchronizing the pointers again. */
        CHECK(equal(table_value(envp, "SOLO_GUEST_ENV"), argv[2]));
        return 0;
    }
    CHECK(argc == 1);
    CHECK(!check_getopt());
    char** original = GUEST_ENVIRON;
    char* repointed[] = {"SOLO_GUEST_ENV=repointed", NULL};
    GUEST_ENVIRON = repointed;
    CHECK(!check_readers());
    CHECK(!check_mutators());
    GUEST_ENVIRON = original;

    const char* slash = strrchr(argv[0], '/');
    CHECK(slash != NULL);
    char* path;
    CHECK(asprintf(&path, "PATH=%.*s", (int)(slash - argv[0]), argv[0]) > 0);
    CHECK(!check_exec(argv[0], path));
    free(path);
    puts("guest environment readers=ok mutators=ok exec=ok");
    return 0;
}
