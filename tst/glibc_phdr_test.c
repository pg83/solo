#ifdef PHDR_LIBRARY
static int number = 7;
static int* volatile pointer = &number;

int phdrValue(void) {
    return *pointer;
}
#else
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int solo;
static pthread_barrier_t start;

static void require(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "program headers: %s\n", message);
        _Exit(1);
    }
}

struct Snapshot {
    unsigned count;
    unsigned long long adds;
    const ElfW(Phdr)* host;
};

static int inspect(struct dl_phdr_info* info, size_t size, void* opaque) {
    struct Snapshot* snapshot = opaque;

    require(size >= offsetof(struct dl_phdr_info, dlpi_subs) + sizeof(info->dlpi_subs), "short dl_phdr_info");
    require(!snapshot->count || snapshot->adds == info->dlpi_adds, "counter changed without loading");
    require(info->dlpi_subs == 0, "unexpected unload");
    snapshot->adds = info->dlpi_adds;
    ++snapshot->count;
    if (solo && (!strcmp(info->dlpi_name, "solo") || !strcmp(info->dlpi_name, "/proc/self/exe"))) {
        snapshot->host = info->dlpi_phdr;
        for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
            require(info->dlpi_phdr[index].p_type != PT_DYNAMIC, "host exposes unrebased dynamic entries");
        }
    }
    return 0;
}

static struct Snapshot snapshot(void) {
    struct Snapshot result = {0};

    require(dl_iterate_phdr(inspect, &result) == 0, "iteration failed");
    require(result.adds >= result.count, "counter is smaller than the image list");
    require(!solo || result.host != NULL, "host image missing");
    return result;
}

static void* firstWalk(void* opaque) {
    struct Snapshot* first = opaque;

    pthread_barrier_wait(&start);
    *first = snapshot();
    for (int round = 0; round < 16; ++round) {
        struct Snapshot next = snapshot();

        require(next.host == first->host && next.count == first->count && next.adds == first->adds, "header snapshot changed");
    }
    return NULL;
}

struct LoadWalk {
    const char* path;
    unsigned trigger;
    unsigned count;
    void* handle;
    unsigned long long highestAdds;
    unsigned long long libraryAdds;
};

static int loadDuringWalk(struct dl_phdr_info* info, size_t size, void* opaque) {
    struct LoadWalk* walk = opaque;

    (void)size;
    if (walk->count++ == walk->trigger) {
        walk->handle = dlopen(walk->path, RTLD_NOW);
        require(walk->handle != NULL, "callback dlopen failed");
    }
    if (info->dlpi_adds > walk->highestAdds) {
        walk->highestAdds = info->dlpi_adds;
    }
    if (!strcmp(info->dlpi_name, walk->path)) {
        walk->libraryAdds = info->dlpi_adds;
    }
    return 0;
}

static void loadAndCheck(const char* path, unsigned trigger) {
    struct Snapshot before = snapshot();
    struct LoadWalk walk = {.path = path, .trigger = trigger};

    require(dl_iterate_phdr(loadDuringWalk, &walk) == 0 && walk.handle != NULL, "reentrant walk failed");

    struct Snapshot after = snapshot();

    require(after.adds == before.adds + 1 && after.count == before.count + 1, "load was not counted exactly once");
    if (walk.libraryAdds) {
        require(walk.libraryAdds == after.adds, "new image carries an old counter");
    } else {
        // A snapshot must not count a library that was loaded too late to
        // appear in it: consumers need to see the change on their next walk.
        require(walk.highestAdds == before.adds, "snapshot counts an image it did not report");
    }
    require(trigger != 0 || walk.libraryAdds != 0, "host callback load missing from guest walk");
    int (*value)(void) = (int (*)(void))dlsym(walk.handle, "phdrValue");

    require(value != NULL && value() == 7, "RELR relocation failed");
    require(dlopen(path, RTLD_NOW) == walk.handle, "repeated dlopen changed the handle");
    require(snapshot().adds == after.adds, "repeated dlopen incremented the counter");
}

struct DynamicCheck {
    const char* path;
    long tag;
    unsigned found;
};

static int checkDynamic(struct dl_phdr_info* info, size_t size, void* opaque) {
    struct DynamicCheck* check = opaque;

    (void)size;
    if (strcmp(info->dlpi_name, check->path)) {
        return 0;
    }
    for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr)* header = &info->dlpi_phdr[index];

        if (header->p_type != PT_DYNAMIC) {
            continue;
        }
        const ElfW(Dyn)* entry = (const ElfW(Dyn)*)(info->dlpi_addr + header->p_vaddr);

        for (; entry->d_tag != DT_NULL; ++entry) {
            if (entry->d_tag == check->tag) {
                require(entry->d_un.d_ptr == 0, "empty relocation table was rebased");
                ++check->found;
            }
        }
    }
    return 0;
}

static int stopWalk(struct dl_phdr_info* info, size_t size, void* opaque) {
    (void)info;
    (void)size;
    ++*(int*)opaque;
    return 73;
}

int main(int argc, char** argv) {
    require(argc == 4, "expected runtime and two libraries");
    solo = !strcmp(argv[1], "solo");
    pthread_t threads[8];
    struct Snapshot first[8];

    require(!pthread_barrier_init(&start, NULL, 8), "barrier initialization failed");
    for (int index = 0; index < 8; ++index) {
        require(!pthread_create(&threads[index], NULL, firstWalk, &first[index]), "thread creation failed");
    }
    for (int index = 0; index < 8; ++index) {
        require(!pthread_join(threads[index], NULL), "thread join failed");
        require(first[index].host == first[0].host, "host header pointer differs between threads");
    }
    require(!pthread_barrier_destroy(&start), "barrier destruction failed");
    int stopped = 0;

    require(dl_iterate_phdr(stopWalk, &stopped) == 73 && stopped == 1, "callback stop was ignored");
    loadAndCheck(argv[2], 0);
    loadAndCheck(argv[3], 1);
    struct DynamicCheck rela = {argv[2], DT_RELA, 0};
    struct DynamicCheck rel = {argv[3], DT_REL, 0};

    require(!dl_iterate_phdr(checkDynamic, &rela) && rela.found, "missing empty RELA table");
    require(!dl_iterate_phdr(checkDynamic, &rel) && rel.found, "missing empty REL table");
    puts("program headers: concurrent first walk, load counters, empty relocations: ok");
    return 0;
}
#endif
