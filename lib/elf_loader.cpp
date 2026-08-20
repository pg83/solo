#include "elf_loader.h"

#include "dlfcn.h"
#include "bionic_shim.h"
#include "glibc_shim.h"
#include "thread_tls.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace dyn;

#ifndef DT_RELR
    #define DT_RELR 36
    #define DT_RELRSZ 35
    #define DT_RELRENT 37
#endif

#ifndef DT_RUNPATH
    #define DT_RUNPATH 29
#endif

#ifndef DT_FLAGS
    #define DT_FLAGS 30
#endif

#ifndef DF_BIND_NOW
    #define DF_BIND_NOW 0x8
#endif

#ifndef DF_SYMBOLIC
    #define DF_SYMBOLIC 0x2
#endif

#ifndef DT_FLAGS_1
    #define DT_FLAGS_1 0x6ffffffb
#endif

#ifndef DF_1_NOW
    #define DF_1_NOW 0x1
#endif

// The dynamic relocations of the supported architectures under one set of
// names; numeric values, because libc elf.h coverage varies.
#if defined(__x86_64__)
    #define ELF_MACHINE EM_X86_64
    #define R_ARCH_ABS64 1 /* R_ARCH_ABS64 */
    #define R_ARCH_GLOB_DAT 6
    #define R_ARCH_JUMP_SLOT 7
    #define R_ARCH_RELATIVE 8
    #define R_ARCH_TLS_DTPMOD 16 /* R_ARCH_TLS_DTPMOD */
    #define R_ARCH_TLS_DTPREL 17 /* R_ARCH_TLS_DTPREL */
    #define R_ARCH_TLS_TPREL 18 /* R_ARCH_TLS_TPREL */
    #define R_ARCH_TLSDESC 36
    #define R_ARCH_IRELATIVE 37
#elif defined(__aarch64__)
    #define ELF_MACHINE EM_AARCH64
    #define R_ARCH_ABS64 257 /* R_AARCH64_ABS64 */
    #define R_ARCH_GLOB_DAT 1025
    #define R_ARCH_JUMP_SLOT 1026
    #define R_ARCH_RELATIVE 1027
    #define R_ARCH_TLS_DTPMOD 1028
    #define R_ARCH_TLS_DTPREL 1029
    #define R_ARCH_TLS_TPREL 1030
    #define R_ARCH_TLSDESC 1031
    #define R_ARCH_IRELATIVE 1032
#else
    #error "unsupported architecture"
#endif

#ifndef STT_GNU_IFUNC
    #define STT_GNU_IFUNC 10
#endif

namespace {
    [[noreturn]] static void throwError(const char* format, ...) {
        std::array<char, 1024> buffer;
        va_list arguments;

        va_start(arguments, format);
        vsnprintf(buffer.data(), buffer.size(), format, arguments);
        va_end(arguments);

        throw std::runtime_error(buffer.data());
    }

    static uintptr_t alignDown(uintptr_t value, uintptr_t alignment) {
        return value & ~(alignment - 1);
    }

    static uintptr_t alignUp(uintptr_t value, uintptr_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    static int segmentProtection(uint32_t flags) {
        int protection = 0;

        if (flags & PF_R) {
            protection |= PROT_READ;
        }
        if (flags & PF_W) {
            protection |= PROT_WRITE;
        }
        if (flags & PF_X) {
            protection |= PROT_EXEC;
        }

        return protection;
    }

    // Surplus static TLS for initial-exec guests. An initial-exec GOT slot is
    // one process-wide number added to every thread's own thread pointer, so
    // the storage it names must sit at the same thread-pointer-relative
    // offset in every thread. The arena is ordinary thread_local data of the
    // host executable, which gives it exactly that property: unmodified musl
    // lays out a copy per thread and seeds threads created later from the
    // executable's TLS template, into which the loader writes each placed
    // guest's own template. The sentinel byte keeps the arena in .tdata; an
    // all-zero arena would land in .tbss, which has no template bytes to
    // write guest initial values into.
    constexpr size_t staticTlsSize = 16 * 1024;
    constexpr size_t staticTlsAlignment = 64;

    struct StaticTlsArena {
        alignas(staticTlsAlignment) unsigned char bytes[staticTlsSize];
        unsigned char sentinel;
    };

    thread_local StaticTlsArena staticTlsArena = {{}, 1};

    // Finding the arena inside the executable's TLS template without
    // re-deriving the linker's thread-pointer layout: search the template for
    // this marker's bytes, then shift by the marker-to-arena distance, which
    // is the same in the template and in every thread's copy of it.
    thread_local unsigned char staticTlsMarker[16] = {
        0x53, 0x6f, 0x4c, 0x6f, 0x9d, 0x11, 0xc4, 0x7e,
        0x2a, 0x68, 0xb0, 0xf5, 0x3c, 0x81, 0xd6, 0x4b,
    };

    // An ifunc resolver call. The aarch64 ABI hands resolvers the hwcaps so
    // they can pick an implementation without reading the auxv themselves;
    // bit 62 of the first argument says the second one is present.
    static uintptr_t resolveIfunc(uintptr_t resolver) {
#if defined(__x86_64__)
        return reinterpret_cast<uintptr_t (*)()>(resolver)();
#elif defined(__aarch64__)
        struct {
            unsigned long size;
            unsigned long hwcap;
            unsigned long hwcap2;
        } arguments = {
            sizeof(arguments),
            getauxval(AT_HWCAP),
            getauxval(AT_HWCAP2),
        };

        return reinterpret_cast<uintptr_t (*)(unsigned long, const void*)>(resolver)(arguments.hwcap | (1UL << 62), &arguments);
#endif
    }

    static uintptr_t threadPointer() {
        uintptr_t pointer;

#if defined(__x86_64__)
        // musl keeps the pthread self pointer, whose value is the thread
        // pointer itself, at %fs:0.
        __asm__("mov %%fs:0, %0" : "=r"(pointer));
#elif defined(__aarch64__)
        __asm__("mrs %0, tpidr_el0" : "=r"(pointer));
#endif

        return pointer;
    }

    struct File {
        explicit File(const std::string& path);

        ~File();

        void read(void* destination, size_t size, off_t offset) const;

        int descriptor_;
    };

    struct LinkMap;

    struct Definition {
        uintptr_t address = 0;
        LinkMap* image = nullptr;
        Elf64_Sym* symbol = nullptr;

        explicit operator bool() const noexcept;
    };

    struct Dependency {
        std::string name;
        void* handle = nullptr;
        LinkMap* image = nullptr;
    };

    struct TlsDescArgument {
        const LinkMap* image;
        uintptr_t offset;
    };

    struct LinkMap {
        enum class State {
            Loading,
            Ready,
            Failed,
        };

        std::string path;
        std::string soname;
        // The image's library search paths with $ORIGIN substituted; per the
        // ld.so rules at most one of the two is in effect.
        std::string rpath;
        std::string runPath;
        uintptr_t base = 0;
        uintptr_t mapStart = 0;
        size_t mapSize = 0;
        std::vector<Elf64_Phdr> programHeaders;

        Elf64_Dyn* dynamic = nullptr;
        const char* strings = nullptr;
        size_t stringsSize = 0;
        Elf64_Sym* symbols = nullptr;
        size_t symbolCount = 0;
        uint32_t* gnuHash = nullptr;
        uint32_t* sysvHash = nullptr;
        Elf64_Half* symbolVersions = nullptr;
        std::vector<std::string_view> versionNames;
        std::vector<Dependency> dependencies;
        bool glibcAbi = false;
        bool bionicAbi = false;

        Elf64_Rela* relocations = nullptr;
        size_t relocationCount = 0;
        Elf64_Rela* pltRelocations = nullptr;
        size_t pltRelocationCount = 0;
        Elf64_Addr* relativeRelocations = nullptr;
        size_t relativeRelocationCount = 0;
        uintptr_t pltGot = 0;
        bool bindNow = false;
        // DT_SYMBOLIC / -Bsymbolic: the image's own definitions win for its
        // own references.
        bool symbolic = false;
        // RTLD_DEEPBIND: the local dependency closure is searched before the
        // global scope instead of after it.
        bool deepBind = false;

        uintptr_t initializer = 0;
        uintptr_t initializerArray = 0;
        size_t initializerCount = 0;
        uintptr_t finalizer = 0;
        uintptr_t finalizerArray = 0;
        size_t finalizerCount = 0;
        uintptr_t relroStart = 0;
        size_t relroSize = 0;

        size_t tlsModule = 0;
        uintptr_t tlsTemplate = 0;
        size_t tlsFileSize = 0;
        size_t tlsMemorySize = 0;
        size_t tlsAlignment = 0;
        // Thread-pointer-relative offset of the module's block in the static
        // TLS arena: negative on x86-64 (TLS below the thread pointer),
        // positive on aarch64 (above it), and never 0, which marks modules
        // served from the dynamic per-thread blocks instead.
        intptr_t staticTlsOffset = 0;

        std::unique_ptr<ElfImage> wrapper;

        State state = State::Loading;

        void parseDynamic();
        void parseVersions(uintptr_t needAddress, size_t needCount, uintptr_t definitionAddress, size_t definitionCount);
        void setVersionName(size_t index, size_t nameOffset);
        size_t countSymbols() const noexcept;
        std::string substituteOrigin(std::string_view directories) const;
        std::string_view symbolVersion(size_t symbolIndex) const noexcept;
        Definition findSymbol(const std::string_view& name, const std::string_view& version) noexcept;
        Definition matchSymbol(size_t index, const std::string_view& name, const std::string_view& version) noexcept;
        void* tlsAddress(size_t offset) const;
        void applyRelativeRelocations();
        void protect();
        void applyRelro();
        void runInitializers();
        void runFinalizers();
    };

    struct DeferredRelocation {
        LinkMap* image;
        const Elf64_Rela* relocation;
    };

    struct MarkFailed {
        explicit MarkFailed(LinkMap& image);
        ~MarkFailed();

        LinkMap& image_;
    };

    // The image whose DT_NEEDED list is being resolved, for its search paths.
    // Nested loads save and restore the previous requester.
    struct ScopedRequester {
        ScopedRequester(LinkMap*& slot, LinkMap& image);
        ~ScopedRequester();

        LinkMap*& slot_;
        LinkMap* previous_;
    };

    struct StringHash {
        using is_transparent = void;

        size_t operator()(const std::string_view& value) const noexcept;
    };

    extern "C" uintptr_t elfTlsDescEntry();
    extern "C" uintptr_t elfPltResolveEntry();

    struct Loader {
        Loader();

        static Loader& instance();

        LinkMap* load(const std::string_view& requestedPath, int flags);
        void runPendingInitializers();

        void* lookup(LinkMap& image, std::string_view name, std::string_view version);
        void* lookupGlobal(std::string_view name);
        void* lookupNext(const void* caller, std::string_view name, std::string_view version);
        void makeGlobal(LinkMap& image);

        bool findAddress(const void* address, ElfAddress* res);
        int iterateProgramHeaders(ElfProgramHeaderCallback& callback);

        LinkMap* findByName(const std::string_view& name) const noexcept;
        LinkMap* findByPath(const std::string& path) const noexcept;

        static std::optional<std::string> realPath(const std::string& path);
        static std::optional<std::string> inDirectory(const std::string_view& directory, const std::string_view& name);
        static std::optional<std::string> inSearchPath(std::string_view directories, const std::string_view& name, bool emptyIsCurrentDirectory);
        static std::optional<std::string> inCache(const std::string_view& name);

        std::optional<std::string> resolvePath(const std::string_view& path) const;
        void rememberLibraryDirectory(const std::string& path);

        size_t addTlsModule();
        void initializeStaticTls();
        void allocateStaticTls(LinkMap& image);

        static bool isGlibcDependency(const std::string_view& name) noexcept;
        void loadDependencies(LinkMap& image);

        static Definition searchScope(LinkMap& image, const std::string_view& name, const std::string_view& version);
        Definition resolveSymbol(LinkMap& image, size_t symbolIndex);
        void debugBinding(const LinkMap& image, const std::string_view& name, const char* provider) const;
        static void* materialize(Definition definition);

        bool applyRelocation(LinkMap& image, const Elf64_Rela& relocation, bool allowIfunc);
        void applyRelocations(LinkMap& image, std::vector<DeferredRelocation>& deferred, bool lazy);
        void* pltResolve(LinkMap& image, size_t index);
        static void runAllFinalizers();

        std::recursive_mutex mutex_;
        std::vector<std::unique_ptr<LinkMap>> images_;
        std::unordered_map<std::string, LinkMap*, StringHash, std::equal_to<>> imagesByName_;
        std::map<uintptr_t, LinkMap*> imagesByAddress_;
        size_t tlsModuleCount_ = 0;
        // The arena's thread-pointer-relative offset, its bytes inside the
        // executable's TLS template, and the bump allocator's high mark.
        intptr_t staticTlsArenaOffset_ = 0;
        unsigned char* staticTlsTemplate_ = nullptr;
        size_t staticTlsUsed_ = 0;
        std::string libraryDirectory_;
        LinkMap* requester_ = nullptr;
        std::vector<LinkMap*> pendingInitializers_;
        bool bindNow_ = false;
        bool debugLibs_ = false;
        bool debugBindings_ = false;
        // Images whose symbols every later relocation may use, in load order.
        std::vector<LinkMap*> globalImages_;
    };

    struct LoadedElf final: public ElfImage {
        explicit LoadedElf(LinkMap& image);

        void* lookup(std::string_view symbol) const override;
        void* lookupVersion(std::string_view symbol, std::string_view version) const override;
        std::string_view path() const override;
        uintptr_t base() const override;
        const void* dynamicSection() const override;

        LinkMap& image_;
    };
}

File::File(const std::string& path)
    : descriptor_(open(path.c_str(), O_RDONLY | O_CLOEXEC))
{
    if (descriptor_ < 0) {
        throwError("open(%s): %s", path.c_str(), strerror(errno));
    }
}

File::~File() {
    if (descriptor_ >= 0) {
        close(descriptor_);
    }
}

void File::read(void* destination, size_t size, off_t offset) const {
    auto* cursor = static_cast<unsigned char*>(destination);

    while (size) {
        auto result = pread(descriptor_, cursor, size, offset);

        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            throwError("pread: %s", result ? strerror(errno) : "unexpected EOF");
        }

        cursor += result;
        size -= result;
        offset += result;
    }
}

Definition::operator bool() const noexcept {
    return address != 0;
}

size_t StringHash::operator()(const std::string_view& value) const noexcept {
    return std::hash<std::string_view>()(value);
}

MarkFailed::MarkFailed(LinkMap& image)
    : image_(image)
{
}

MarkFailed::~MarkFailed() {
    if (image_.state == LinkMap::State::Loading) {
        image_.state = LinkMap::State::Failed;
    }
}

ScopedRequester::ScopedRequester(LinkMap*& slot, LinkMap& image)
    : slot_(slot)
    , previous_(slot)
{
    slot_ = &image;
}

ScopedRequester::~ScopedRequester() {
    slot_ = previous_;
}

// Registered before any loaded DSO can register its own atexit handlers, so
// like glibc's _dl_fini it runs after them.
Loader::Loader() {
    bindNow_ = getenv("LD_BIND_NOW") != nullptr;
    if (const auto* debug = getenv("DL_DEBUG"); debug) {
        std::string_view flags(debug);

        debugLibs_ = flags.find("libs") != std::string_view::npos || flags == "all";
        debugBindings_ = flags.find("bindings") != std::string_view::npos || flags == "all";
    }
    initializeStaticTls();
    atexit(runAllFinalizers);
}

Loader& Loader::instance() {
    static auto* loader = new Loader();

    return *loader;
}

LinkMap* Loader::load(const std::string_view& requestedPath, int flags) {
    std::lock_guard lock(mutex_);

    if (requestedPath.empty()) {
        throwError("empty ELF image path");
    }

    if (auto* image = findByName(requestedPath); image) {
        if (image->state == LinkMap::State::Failed) {
            throwError("%s: a previous load failed", image->path.c_str());
        }
        if (flags & RTLD_GLOBAL) {
            makeGlobal(*image);
        }

        return image;
    }

    auto resolved = resolvePath(requestedPath);

    if (!resolved) {
        throwError("cannot resolve ELF image: %.*s", static_cast<int>(requestedPath.size()), requestedPath.data());
    }

    if (auto* image = findByPath(*resolved); image) {
        if (image->state == LinkMap::State::Failed) {
            throwError("%s: a previous load failed", image->path.c_str());
        }
        if (flags & RTLD_GLOBAL) {
            makeGlobal(*image);
        }

        return image;
    }
    if (flags & RTLD_NOLOAD) {
        throwError("%s: image is not loaded", resolved->c_str());
    }

    rememberLibraryDirectory(*resolved);

    File file(*resolved);

    Elf64_Ehdr header;

    file.read(&header, sizeof(header), 0);
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != ELF_MACHINE || header.e_type != ET_DYN || header.e_phentsize != sizeof(Elf64_Phdr)) {
        throwError("%s: not an ET_DYN ELF for this machine", resolved->c_str());
    }

    auto imageOwner = std::make_unique<LinkMap>();
    auto& image = *imageOwner;

    image.path = *resolved;
    image.programHeaders.resize(header.e_phnum);
    file.read(image.programHeaders.data(), image.programHeaders.size() * sizeof(Elf64_Phdr), static_cast<off_t>(header.e_phoff));

    auto pageSize = sysconf(_SC_PAGESIZE);

    if (pageSize <= 0) {
        throwError("%s: cannot determine page size", image.path.c_str());
    }

    uintptr_t minimumAddress = UINTPTR_MAX;
    uintptr_t maximumAddress = 0;

    for (const auto& programHeader : image.programHeaders) {
        if (programHeader.p_type != PT_LOAD) {
            continue;
        }

        auto start = alignDown(programHeader.p_vaddr, pageSize);
        auto end = alignUp(programHeader.p_vaddr + programHeader.p_memsz, pageSize);

        minimumAddress = std::min(minimumAddress, start);
        maximumAddress = std::max(maximumAddress, end);
    }

    if (minimumAddress == UINTPTR_MAX || maximumAddress <= minimumAddress) {
        throwError("%s: no loadable segments", image.path.c_str());
    }

    image.mapSize = maximumAddress - minimumAddress;
    // A reservation for the whole span; the segments are mapped into it from
    // the file below.
    auto* mapping = mmap(nullptr, image.mapSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mapping == MAP_FAILED) {
        throwError("%s: mmap: %s", image.path.c_str(), strerror(errno));
    }

    image.mapStart = reinterpret_cast<uintptr_t>(mapping);
    image.base = image.mapStart - minimumAddress;

    auto* imagePointer = &image;
    images_.push_back(std::move(imageOwner));
    imagesByName_.emplace(image.path, &image);
    imagesByName_.emplace(std::string(requestedPath), &image);
    imagesByAddress_.emplace(image.mapStart, &image);

    MarkFailed markFailed(image);

    for (const auto& programHeader : image.programHeaders) {
        if (programHeader.p_type == PT_LOAD) {
            if (programHeader.p_filesz > programHeader.p_memsz) {
                throwError("%s: PT_LOAD file size exceeds memory size", image.path.c_str());
            }
            if ((programHeader.p_vaddr - programHeader.p_offset) % pageSize) {
                throwError("%s: PT_LOAD file offset is not congruent with its address", image.path.c_str());
            }

            // The segments map from the file, copy-on-write: untouched pages
            // stay shared with the page cache, and /proc/self/maps names the
            // library for debuggers and profilers. Everything is writable
            // until protect() runs, so relocations just work.
            auto start = alignDown(image.base + programHeader.p_vaddr, pageSize);
            auto fileEnd = image.base + programHeader.p_vaddr + programHeader.p_filesz;
            auto memoryEnd = alignUp(image.base + programHeader.p_vaddr + programHeader.p_memsz, pageSize);

            if (programHeader.p_filesz) {
                if (mmap(reinterpret_cast<void*>(start), alignUp(fileEnd, pageSize) - start, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, file.descriptor_, static_cast<off_t>(alignDown(programHeader.p_offset, pageSize))) == MAP_FAILED) {
                    throwError("%s: mmap segment: %s", image.path.c_str(), strerror(errno));
                }
            }
            if (programHeader.p_memsz > programHeader.p_filesz) {
                // The zero-fill tail: the rest of the last file page by hand,
                // fresh anonymous pages beyond it.
                auto anonymousStart = start;

                if (programHeader.p_filesz) {
                    anonymousStart = alignUp(fileEnd, pageSize);
                    memset(reinterpret_cast<void*>(fileEnd), 0, anonymousStart - fileEnd);
                }
                if (anonymousStart < memoryEnd && mmap(reinterpret_cast<void*>(anonymousStart), memoryEnd - anonymousStart, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
                    throwError("%s: mmap zero fill: %s", image.path.c_str(), strerror(errno));
                }
            }
        } else if (programHeader.p_type == PT_DYNAMIC) {
            image.dynamic = reinterpret_cast<Elf64_Dyn*>(image.base + programHeader.p_vaddr);
        } else if (programHeader.p_type == PT_GNU_RELRO) {
            image.relroStart = programHeader.p_vaddr;
            image.relroSize = programHeader.p_memsz;
        } else if (programHeader.p_type == PT_TLS) {
            image.tlsModule = addTlsModule();
            image.tlsTemplate = image.base + programHeader.p_vaddr;
            image.tlsFileSize = programHeader.p_filesz;
            image.tlsMemorySize = programHeader.p_memsz;
            image.tlsAlignment = programHeader.p_align;
        }
    }

    if (!image.dynamic) {
        throwError("%s: missing PT_DYNAMIC", image.path.c_str());
    }
    if (image.tlsModule) {
        allocateStaticTls(image);
    }
    image.parseDynamic();
    if (!image.soname.empty()) {
        imagesByName_.emplace(image.soname, &image);
    }
    loadDependencies(image);

    image.deepBind = (flags & RTLD_DEEPBIND) != 0;

    std::vector<DeferredRelocation> deferred;
    auto lazy = !(flags & RTLD_NOW) && !image.bindNow && !bindNow_;

    applyRelocations(image, deferred, lazy);
    image.protect();

    for (const auto& item : deferred) {
        applyRelocation(*item.image, *item.relocation, true);
    }
    image.applyRelro();

    image.wrapper.reset(new LoadedElf(image));
    image.state = LinkMap::State::Ready;
    if (flags & RTLD_GLOBAL) {
        makeGlobal(image);
    }
    if (debugLibs_) {
        fprintf(stderr, "solo: loaded %s at %#lx%s\n", image.path.c_str(), image.base, lazy ? " (lazy)" : "");
    }
    pendingInitializers_.push_back(&image);

    return imagePointer;
}

// Initializers run without the loader mutex, so a thread an initializer
// spawns can enter the loader; the queue is drained by the public entry once
// the outermost load released the lock.
void Loader::runPendingInitializers() {
    for (;;) {
        LinkMap* image = nullptr;
        {
            std::lock_guard lock(mutex_);

            if (pendingInitializers_.empty()) {
                return;
            }
            image = pendingInitializers_.front();
            pendingInitializers_.erase(pendingInitializers_.begin());
        }
        image->runInitializers();
    }
}

// RTLD_GLOBAL publishes the image's whole local scope, so the global search
// list grows by the dependency closure in breadth-first order, like ld.so.
void Loader::makeGlobal(LinkMap& image) {
    std::deque<LinkMap*> queue({&image});

    while (!queue.empty()) {
        auto* current = queue.front();

        queue.pop_front();
        if (std::find(globalImages_.begin(), globalImages_.end(), current) != globalImages_.end()) {
            continue;
        }
        globalImages_.push_back(current);
        for (const auto& dependency : current->dependencies) {
            if (dependency.image) {
                queue.push_back(dependency.image);
            }
        }
    }
}

void* Loader::lookupGlobal(std::string_view name) {
    std::lock_guard lock(mutex_);

    for (auto* image : globalImages_) {
        if (auto definition = image->findSymbol(name, {}); definition) {
            return materialize(definition);
        }
    }

    return nullptr;
}

void* Loader::lookupNext(const void* caller, std::string_view name, std::string_view version) {
    std::lock_guard lock(mutex_);
    auto needle = reinterpret_cast<uintptr_t>(caller);
    bool after = false;

    for (const auto& image : images_) {
        if (!after) {
            after = needle >= image->mapStart && needle < image->mapStart + image->mapSize;
            continue;
        }
        if (image->state != LinkMap::State::Ready) {
            continue;
        }
        if (auto definition = image->findSymbol(name, version); definition) {
            return materialize(definition);
        }
    }

    return nullptr;
}

void* Loader::lookup(LinkMap& image, std::string_view name, std::string_view version) {
    std::lock_guard lock(mutex_);

    return materialize(searchScope(image, name, version));
}

// Breadth-first over the image and its dependency closure, in load order at
// each depth, matching the search order of ld.so. A dependency backed by a
// static provider is probed at its depth through its handle.
Definition Loader::searchScope(LinkMap& image, const std::string_view& name, const std::string_view& version) {
    if (auto definition = image.findSymbol(name, version); definition) {
        return definition;
    }

    std::unordered_set<LinkMap*> visited({&image});
    std::deque<const Dependency*> queue;
    auto enqueue = [&](const LinkMap& parent) {
        for (const auto& dependency : parent.dependencies) {
            if (!dependency.image || visited.insert(dependency.image).second) {
                queue.push_back(&dependency);
            }
        }
    };
    std::string symbol(name);

    enqueue(image);
    while (!queue.empty()) {
        const auto* dependency = queue.front();

        queue.pop_front();
        if (!dependency->image) {
            if (auto* address = stub_dlsym(dependency->handle, symbol.c_str()); address) {
                return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
            }
            stub_dlerror();
            continue;
        }
        if (auto definition = dependency->image->findSymbol(name, version); definition) {
            return definition;
        }
        enqueue(*dependency->image);
    }

    return {};
}

// Touches only the caller's ThreadTls and the image's immutable TLS metadata,
// so a thread spawned by an initializer can reach its TLS while the loader
// mutex is still held.
void* LinkMap::tlsAddress(size_t offset) const {
    if (offset >= tlsMemorySize) {
        throwError("%s: TLS offset %zu exceeds size %zu", path.c_str(), offset, tlsMemorySize);
    }

    // A module placed in the static arena must be served from it through
    // every TLS model, or general-dynamic and initial-exec accesses to the
    // same variable would see different memory.
    if (staticTlsOffset) {
        return reinterpret_cast<unsigned char*>(threadPointer() + staticTlsOffset) + offset;
    }

    auto* slot = ThreadTls::current()->tlsBlock(tlsModule);

    if (!*slot) {
        auto alignment = std::max(tlsAlignment, sizeof(void*));
        void* block = nullptr;

        if (posix_memalign(&block, alignment, tlsMemorySize)) {
            throwError("%s: cannot allocate TLS block", path.c_str());
        }

        memset(block, 0, tlsMemorySize);
        memcpy(block, reinterpret_cast<const void*>(tlsTemplate), tlsFileSize);
        *slot = block;
    }

    return static_cast<unsigned char*>(*slot) + offset;
}

bool Loader::findAddress(const void* address, ElfAddress* res) {
    std::lock_guard lock(mutex_);
    auto needle = reinterpret_cast<uintptr_t>(address);
    auto found = imagesByAddress_.upper_bound(needle);

    if (found == imagesByAddress_.begin()) {
        return false;
    }
    --found;

    const auto& image = *found->second;

    if (needle >= image.mapStart + image.mapSize) {
        return false;
    }

    *res = ElfAddress{
        image.path,
        reinterpret_cast<void*>(image.base),
    };

    // The nearest defined symbol whose storage covers the address.
    uintptr_t best = 0;

    for (size_t index = 0; index < image.symbolCount; ++index) {
        const auto& symbol = image.symbols[index];
        auto type = ELF64_ST_TYPE(symbol.st_info);

        if (symbol.st_shndx == SHN_UNDEF || (type != STT_FUNC && type != STT_OBJECT && type != STT_GNU_IFUNC)) {
            continue;
        }

        auto start = image.base + symbol.st_value;

        if (needle < start || start < best || symbol.st_name >= image.stringsSize) {
            continue;
        }
        if (symbol.st_size ? needle >= start + symbol.st_size : needle != start) {
            continue;
        }

        best = start;
        res->symbol = image.strings + symbol.st_name;
        res->symbolAddress = reinterpret_cast<void*>(start);
    }

    return true;
}

int Loader::iterateProgramHeaders(ElfProgramHeaderCallback& callback) {
    std::vector<LinkMap*> images;
    {
        std::lock_guard lock(mutex_);
        images.reserve(images_.size());
        for (const auto& image : images_) {
            if (image->state == LinkMap::State::Ready) {
                images.push_back(image.get());
            }
        }
    }

    for (const auto* image : images) {
        void* tlsData = nullptr;
        if (image->staticTlsOffset) {
            tlsData = reinterpret_cast<void*>(threadPointer() + image->staticTlsOffset);
        } else if (image->tlsModule) {
            tlsData = *ThreadTls::current()->tlsBlock(image->tlsModule);
        }
        const ElfProgramHeaders headers{
            image->path.c_str(),
            image->base,
            image->programHeaders.data(),
            static_cast<Elf64_Half>(image->programHeaders.size()),
            image->tlsModule,
            tlsData,
        };
        if (const int result = callback.call(headers); result) {
            return result;
        }
    }

    return 0;
}

LinkMap* Loader::findByName(const std::string_view& name) const noexcept {
    if (auto image = imagesByName_.find(name); image != imagesByName_.end()) {
        return image->second;
    }

    return nullptr;
}

LinkMap* Loader::findByPath(const std::string& path) const noexcept {
    return findByName(path);
}

std::optional<std::string> Loader::realPath(const std::string& path) {
    std::array<char, PATH_MAX> resolved;

    if (!realpath(path.c_str(), resolved.data())) {
        return std::nullopt;
    }

    return std::string(resolved.data());
}

std::optional<std::string> Loader::inDirectory(const std::string_view& directory, const std::string_view& name) {
    std::string candidate(directory);

    if (!candidate.empty() && candidate.back() != '/') {
        candidate.push_back('/');
    }
    candidate.append(name);

    return realPath(candidate);
}

std::optional<std::string> Loader::inSearchPath(std::string_view directories, const std::string_view& name, bool emptyIsCurrentDirectory) {
    while (true) {
        auto separator = directories.find(':');
        auto directory = directories.substr(0, separator);

        if (!directory.empty() || emptyIsCurrentDirectory) {
            if (auto resolved = inDirectory(directory.empty() ? "." : directory, name); resolved) {
                return resolved;
            }
        }
        if (separator == std::string_view::npos) {
            return std::nullopt;
        }
        directories.remove_prefix(separator + 1);
    }
}

// ldconfig's /etc/ld.so.cache, in the standalone new format: a header, an
// entry table, and a string table the entries' offsets index from the start
// of the file. This is how ld.so.conf.d directories reach us without parsing
// the configuration ourselves.
std::optional<std::string> Loader::inCache(const std::string_view& name) {
    struct Header {
        char magic[17];
        char version[3];
        uint32_t count;
        uint32_t stringsLength;
        uint8_t flags;
        uint8_t padding[3];
        uint32_t extensionOffset;
        uint32_t unused[3];
    };
    struct Entry {
        int32_t flags;
        uint32_t key;
        uint32_t value;
        uint32_t osVersion;
        uint64_t hwcap;
    };
    // FLAG_ELF_LIBC6 plus the architecture bits ldconfig stamps on entries.
#if defined(__x86_64__)
    constexpr int32_t architectureFlags = 0x0303;
#elif defined(__aarch64__)
    constexpr int32_t architectureFlags = 0x0a03;
#endif

    auto descriptor = open("/etc/ld.so.cache", O_RDONLY | O_CLOEXEC);

    if (descriptor < 0) {
        return std::nullopt;
    }

    struct stat status;

    if (fstat(descriptor, &status) || static_cast<size_t>(status.st_size) < sizeof(Header)) {
        close(descriptor);
        return std::nullopt;
    }

    auto size = static_cast<size_t>(status.st_size);
    auto* data = static_cast<const char*>(mmap(nullptr, size, PROT_READ, MAP_PRIVATE, descriptor, 0));

    close(descriptor);
    if (data == MAP_FAILED) {
        return std::nullopt;
    }

    std::optional<std::string> resolved;
    const auto& header = *reinterpret_cast<const Header*>(data);

    if (memcmp(header.magic, "glibc-ld.so.cache", sizeof(header.magic)) == 0 && memcmp(header.version, "1.1", sizeof(header.version)) == 0 && sizeof(Header) + header.count * sizeof(Entry) <= size) {
        const auto* entries = reinterpret_cast<const Entry*>(data + sizeof(Header));

        for (uint32_t index = 0; index < header.count && !resolved; ++index) {
            const auto& entry = entries[index];

            // hwcap bits mark glibc-hwcaps subdirectory variants; the
            // baseline library is the right pick.
            if (entry.flags != architectureFlags || entry.hwcap || entry.key >= size || entry.value >= size) {
                continue;
            }
            if (std::string_view(data + entry.key) == name) {
                resolved = std::string(data + entry.value);
            }
        }
    }
    munmap(const_cast<char*>(data), size);

    return resolved;
}

std::optional<std::string> Loader::resolvePath(const std::string_view& path) const {
    if (path.find('/') != std::string_view::npos) {
        return realPath(std::string(path));
    }

    if (const auto* configured = getenv("DL_ELF_LIBRARY_PATH"); configured) {
        if (auto resolved = inSearchPath(configured, path, false); resolved) {
            return resolved;
        }
    }
    if (requester_ && !requester_->rpath.empty()) {
        if (auto resolved = inSearchPath(requester_->rpath, path, false); resolved) {
            return resolved;
        }
    }
    if (const auto* configured = getenv("LD_LIBRARY_PATH"); configured) {
        if (auto resolved = inSearchPath(configured, path, true); resolved) {
            return resolved;
        }
    }
    if (requester_ && !requester_->runPath.empty()) {
        if (auto resolved = inSearchPath(requester_->runPath, path, false); resolved) {
            return resolved;
        }
    }

    if (!libraryDirectory_.empty()) {
        if (auto resolved = inDirectory(libraryDirectory_, path); resolved) {
            return resolved;
        }
    }
    if (auto resolved = inCache(path); resolved) {
        return resolved;
    }

    static constexpr std::array systemDirectories = {
        std::string_view("/usr/lib"),
        std::string_view("/lib"),
        std::string_view("/usr/lib64"),
        std::string_view("/lib64"),
#if defined(__x86_64__)
        std::string_view("/usr/lib/x86_64-linux-gnu"),
        std::string_view("/lib/x86_64-linux-gnu"),
#elif defined(__aarch64__)
        std::string_view("/usr/lib/aarch64-linux-gnu"),
        std::string_view("/lib/aarch64-linux-gnu"),
#endif
    };

    for (auto directory : systemDirectories) {
        if (auto resolved = inDirectory(directory, path); resolved) {
            return resolved;
        }
    }

    return std::nullopt;
}

void Loader::rememberLibraryDirectory(const std::string& path) {
    if (!libraryDirectory_.empty()) {
        return;
    }

    auto slash = path.rfind('/');

    if (slash == std::string::npos) {
        libraryDirectory_ = ".";
    } else if (!slash) {
        libraryDirectory_ = "/";
    } else {
        libraryDirectory_ = path.substr(0, slash);
    }
}

size_t Loader::addTlsModule() {
    return ++tlsModuleCount_;
}

// Locates the arena in the executable's TLS template, which musl's
// pthread_create copies into every new thread, and pins down the arena's
// thread-pointer-relative offset, a link-time constant of the executable.
void Loader::initializeStaticTls() {
    auto* headers = reinterpret_cast<const Elf64_Phdr*>(getauxval(AT_PHDR));
    auto count = getauxval(AT_PHNUM);
    uintptr_t base = 0;
    const Elf64_Phdr* tls = nullptr;

    if (!headers || !count) {
        throwError("static TLS: the auxiliary vector has no program headers");
    }

    for (unsigned long index = 0; index < count; ++index) {
        if (headers[index].p_type == PT_PHDR) {
            base = reinterpret_cast<uintptr_t>(headers) - headers[index].p_vaddr;
        } else if (headers[index].p_type == PT_TLS) {
            tls = &headers[index];
        }
    }
    if (!tls) {
        throwError("static TLS: the executable has no PT_TLS segment");
    }

    auto* image = reinterpret_cast<unsigned char*>(base + tls->p_vaddr);
    auto* marker = static_cast<unsigned char*>(memmem(image, tls->p_filesz, staticTlsMarker, sizeof(staticTlsMarker)));

    if (!marker) {
        throwError("static TLS: the arena marker is not in the executable's TLS template");
    }
    if (memmem(marker + 1, image + tls->p_filesz - marker - 1, staticTlsMarker, sizeof(staticTlsMarker))) {
        throwError("static TLS: the arena marker is ambiguous");
    }

    // The distance between two thread_local objects is the same in the
    // template and in every thread's copy of it.
    auto delta = reinterpret_cast<intptr_t>(staticTlsArena.bytes) - reinterpret_cast<intptr_t>(staticTlsMarker);

    staticTlsTemplate_ = marker + delta;
    if (staticTlsTemplate_ < image || staticTlsTemplate_ + staticTlsSize > image + tls->p_filesz) {
        throwError("static TLS: the arena is outside the executable's TLS template");
    }
    staticTlsArenaOffset_ = reinterpret_cast<intptr_t>(staticTlsArena.bytes) - static_cast<intptr_t>(threadPointer());

    // The template commonly sits in the executable's RELRO region.
    auto pageSize = sysconf(_SC_PAGESIZE);
    auto start = alignDown(reinterpret_cast<uintptr_t>(staticTlsTemplate_), pageSize);
    auto end = alignUp(reinterpret_cast<uintptr_t>(staticTlsTemplate_) + staticTlsSize, pageSize);

    if (pageSize <= 0 || mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ | PROT_WRITE)) {
        throwError("static TLS: mprotect(template): %s", strerror(errno));
    }
}

// Places a freshly loaded module's TLS in the arena, making one
// thread-pointer-relative offset valid in every thread at once, which is what
// initial-exec relocations demand. On overflow the module falls back to the
// dynamic per-thread blocks, and only a later initial-exec reference to it
// fails.
void Loader::allocateStaticTls(LinkMap& image) {
    auto alignment = std::max(image.tlsAlignment, sizeof(void*));

    if (alignment > staticTlsAlignment) {
        return;
    }

    auto offset = alignUp(staticTlsUsed_, alignment);

    if (offset > staticTlsSize || image.tlsMemorySize > staticTlsSize - offset) {
        return;
    }
    staticTlsUsed_ = offset + image.tlsMemorySize;
    image.staticTlsOffset = staticTlsArenaOffset_ + static_cast<intptr_t>(offset);

    // Threads created after this load copy the executable's template, and the
    // loading thread gets its copy here. Threads that already exist keep
    // zeroes: dlopen libraries with TLS before spawning threads that use them.
    memset(staticTlsTemplate_ + offset, 0, image.tlsMemorySize);
    memcpy(staticTlsTemplate_ + offset, reinterpret_cast<const void*>(image.tlsTemplate), image.tlsFileSize);
    memset(staticTlsArena.bytes + offset, 0, image.tlsMemorySize);
    memcpy(staticTlsArena.bytes + offset, reinterpret_cast<const void*>(image.tlsTemplate), image.tlsFileSize);
}

// Bionic's system libraries, spelled without versions: Termux packages are
// bionic-linked and import these from /system, which never enters the
// process — the bionic personality serves them over the same musl runtime.
static bool isBionicDependency(const std::string_view& name) noexcept {
    static constexpr std::array dependencies = {
        std::string_view("libc.so"),
        std::string_view("libm.so"),
        std::string_view("libdl.so"),
        std::string_view("liblog.so"),
    };

    return std::find(dependencies.begin(), dependencies.end(), name) != dependencies.end();
}

bool Loader::isGlibcDependency(const std::string_view& name) noexcept {
    static constexpr std::array dependencies = {
        std::string_view("libc.so.6"),
        std::string_view("libpthread.so.0"),
        std::string_view("libdl.so.2"),
        std::string_view("libm.so.6"),
        std::string_view("librt.so.1"),
        std::string_view("libresolv.so.2"),
        std::string_view("libmvec.so.1"),
        std::string_view("libutil.so.1"),
        std::string_view("libanl.so.1"),
        std::string_view("libnsl.so.1"),
#if defined(__x86_64__)
        std::string_view("ld-linux-x86-64.so.2"),
#elif defined(__aarch64__)
        std::string_view("ld-linux-aarch64.so.1"),
#endif
    };

    return std::find(dependencies.begin(), dependencies.end(), name) != dependencies.end();
}

void Loader::loadDependencies(LinkMap& image) {
    ScopedRequester requester(requester_, image);

    for (auto* entry = image.dynamic; entry->d_tag != DT_NULL; ++entry) {
        if (entry->d_tag != DT_NEEDED) {
            continue;
        }
        if (entry->d_un.d_val >= image.stringsSize) {
            throwError("%s: DT_NEEDED outside the string table", image.path.c_str());
        }

        std::string needed(image.strings + entry->d_un.d_val);

        if (isGlibcDependency(needed)) {
            image.glibcAbi = true;
            continue;
        }
        if (isBionicDependency(needed)) {
            image.bionicAbi = true;
            continue;
        }

        auto* handle = stub_dlopen(needed.c_str(), RTLD_LAZY | RTLD_LOCAL);

        if (!handle) {
            auto* error = stub_dlerror();
            throwError("%s: cannot load %s: %s", image.path.c_str(), needed.c_str(), error ? error : "unknown error");
        }

        image.dependencies.push_back({needed, handle, findByName(needed)});
    }
}

void LinkMap::setVersionName(size_t index, size_t nameOffset) {
    if (nameOffset >= stringsSize) {
        throwError("%s: version name outside the string table", path.c_str());
    }
    if (index >= versionNames.size()) {
        versionNames.resize(index + 1);
    }

    versionNames[index] = strings + nameOffset;
}

void LinkMap::parseVersions(uintptr_t needAddress, size_t needCount, uintptr_t definitionAddress, size_t definitionCount) {
    if (needAddress) {
        auto* need = reinterpret_cast<Elf64_Verneed*>(base + needAddress);

        for (size_t index = 0; index < needCount; ++index) {
            auto* auxiliary = reinterpret_cast<Elf64_Vernaux*>(reinterpret_cast<char*>(need) + need->vn_aux);

            for (size_t item = 0; item < need->vn_cnt; ++item) {
                setVersionName(auxiliary->vna_other & 0x7fff, auxiliary->vna_name);
                if (!auxiliary->vna_next) {
                    break;
                }
                auxiliary = reinterpret_cast<Elf64_Vernaux*>(reinterpret_cast<char*>(auxiliary) + auxiliary->vna_next);
            }
            if (!need->vn_next) {
                break;
            }
            need = reinterpret_cast<Elf64_Verneed*>(reinterpret_cast<char*>(need) + need->vn_next);
        }
    }

    if (definitionAddress) {
        auto* definition = reinterpret_cast<Elf64_Verdef*>(base + definitionAddress);

        for (size_t index = 0; index < definitionCount; ++index) {
            auto* auxiliary = reinterpret_cast<Elf64_Verdaux*>(reinterpret_cast<char*>(definition) + definition->vd_aux);

            setVersionName(definition->vd_ndx & 0x7fff, auxiliary->vda_name);
            if (!definition->vd_next) {
                break;
            }
            definition = reinterpret_cast<Elf64_Verdef*>(reinterpret_cast<char*>(definition) + definition->vd_next);
        }
    }
}

void LinkMap::parseDynamic() {
    uintptr_t needVersions = 0;
    size_t needVersionCount = 0;
    uintptr_t definedVersions = 0;
    size_t definedVersionCount = 0;
    size_t relocationSize = 0;
    size_t relocationEntrySize = sizeof(Elf64_Rela);
    size_t pltRelocationSize = 0;
    size_t relativeRelocationSize = 0;
    size_t relativeRelocationEntrySize = sizeof(Elf64_Addr);
    size_t sonameOffset = SIZE_MAX;
    size_t rpathOffset = SIZE_MAX;
    size_t runPathOffset = SIZE_MAX;

    for (auto* entry = dynamic; entry->d_tag != DT_NULL; ++entry) {
        switch (entry->d_tag) {
            case DT_STRTAB:
                strings = reinterpret_cast<const char*>(base + entry->d_un.d_ptr);
                break;
            case DT_STRSZ:
                stringsSize = entry->d_un.d_val;
                break;
            case DT_SYMTAB:
                symbols = reinterpret_cast<Elf64_Sym*>(base + entry->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                gnuHash = reinterpret_cast<uint32_t*>(base + entry->d_un.d_ptr);
                break;
            case DT_HASH:
                sysvHash = reinterpret_cast<uint32_t*>(base + entry->d_un.d_ptr);
                break;
            case DT_VERSYM:
                symbolVersions = reinterpret_cast<Elf64_Half*>(base + entry->d_un.d_ptr);
                break;
            case DT_VERNEED:
                needVersions = entry->d_un.d_ptr;
                break;
            case DT_VERNEEDNUM:
                needVersionCount = entry->d_un.d_val;
                break;
            case DT_VERDEF:
                definedVersions = entry->d_un.d_ptr;
                break;
            case DT_VERDEFNUM:
                definedVersionCount = entry->d_un.d_val;
                break;
            case DT_RELA:
                relocations = reinterpret_cast<Elf64_Rela*>(base + entry->d_un.d_ptr);
                break;
            case DT_RELASZ:
                relocationSize = entry->d_un.d_val;
                break;
            case DT_RELAENT:
                relocationEntrySize = entry->d_un.d_val;
                break;
            case DT_JMPREL:
                pltRelocations = reinterpret_cast<Elf64_Rela*>(base + entry->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                pltRelocationSize = entry->d_un.d_val;
                break;
            case DT_PLTGOT:
                pltGot = base + entry->d_un.d_ptr;
                break;
            case DT_BIND_NOW:
                bindNow = true;
                break;
            case DT_SYMBOLIC:
                symbolic = true;
                break;
            case DT_FLAGS:
                bindNow |= (entry->d_un.d_val & DF_BIND_NOW) != 0;
                symbolic |= (entry->d_un.d_val & DF_SYMBOLIC) != 0;
                break;
            case DT_FLAGS_1:
                bindNow |= (entry->d_un.d_val & DF_1_NOW) != 0;
                break;
            case DT_RELR:
                relativeRelocations = reinterpret_cast<Elf64_Addr*>(base + entry->d_un.d_ptr);
                break;
            case DT_RELRSZ:
                relativeRelocationSize = entry->d_un.d_val;
                break;
            case DT_RELRENT:
                relativeRelocationEntrySize = entry->d_un.d_val;
                break;
            case DT_INIT:
                initializer = base + entry->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                initializerArray = base + entry->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                initializerCount = entry->d_un.d_val / sizeof(uintptr_t);
                break;
            case DT_FINI:
                finalizer = base + entry->d_un.d_ptr;
                break;
            case DT_FINI_ARRAY:
                finalizerArray = base + entry->d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                finalizerCount = entry->d_un.d_val / sizeof(uintptr_t);
                break;
            case DT_SONAME:
                sonameOffset = entry->d_un.d_val;
                break;
            case DT_RPATH:
                rpathOffset = entry->d_un.d_val;
                break;
            case DT_RUNPATH:
                runPathOffset = entry->d_un.d_val;
                break;
            default:
                break;
        }
    }

    if (!strings || !symbols || (!gnuHash && !sysvHash)) {
        throwError("%s: missing dynamic string, symbol, or hash table", path.c_str());
    }
    if (relocationSize && relocationEntrySize != sizeof(Elf64_Rela)) {
        throwError("%s: unsupported RELA entry size %zu", path.c_str(), relocationEntrySize);
    }
    if (relativeRelocationSize && relativeRelocationEntrySize != sizeof(Elf64_Addr)) {
        throwError("%s: unsupported RELR entry size %zu", path.c_str(), relativeRelocationEntrySize);
    }
    if (sonameOffset < stringsSize) {
        soname = strings + sonameOffset;
    }
    // DT_RUNPATH supersedes DT_RPATH when both are present.
    if (runPathOffset < stringsSize) {
        runPath = substituteOrigin(strings + runPathOffset);
    } else if (rpathOffset < stringsSize) {
        rpath = substituteOrigin(strings + rpathOffset);
    }

    relocationCount = relocationSize / sizeof(Elf64_Rela);
    pltRelocationCount = pltRelocationSize / sizeof(Elf64_Rela);
    relativeRelocationCount = relativeRelocationSize / sizeof(Elf64_Addr);
    symbolCount = countSymbols();
    parseVersions(needVersions, needVersionCount, definedVersions, definedVersionCount);
}

// The dynamic section has no symbol count; recover it from the GNU hash
// table as one past the highest chain index.
std::string LinkMap::substituteOrigin(std::string_view directories) const {
    auto slash = path.rfind('/');
    std::string origin(slash == std::string::npos ? "." : path.substr(0, slash));
    std::string result;

    while (!directories.empty()) {
        auto dollar = directories.find('$');

        if (dollar == std::string_view::npos) {
            result.append(directories);
            break;
        }
        result.append(directories.substr(0, dollar));
        directories.remove_prefix(dollar);
        if (directories.starts_with("${ORIGIN}")) {
            result.append(origin);
            directories.remove_prefix(9);
        } else if (directories.starts_with("$ORIGIN")) {
            result.append(origin);
            directories.remove_prefix(7);
        } else {
            result.push_back('$');
            directories.remove_prefix(1);
        }
    }

    return result;
}

size_t LinkMap::countSymbols() const noexcept {
    if (!gnuHash) {
        // The SysV nchain is the dynamic symbol table's size.
        return sysvHash[1];
    }

    auto bucketCount = gnuHash[0];
    auto symbolOffset = gnuHash[1];
    auto bloomSize = gnuHash[2];
    const auto* bloom = reinterpret_cast<const Elf64_Xword*>(gnuHash + 4);
    const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
    const auto* chains = buckets + bucketCount;
    size_t count = symbolOffset;

    for (uint32_t bucket = 0; bucket < bucketCount; ++bucket) {
        auto index = buckets[bucket];

        if (index < symbolOffset) {
            continue;
        }
        while (!(chains[index - symbolOffset] & 1)) {
            ++index;
        }
        count = std::max(count, static_cast<size_t>(index) + 1);
    }

    return count;
}

std::string_view LinkMap::symbolVersion(size_t symbolIndex) const noexcept {
    if (!symbolVersions) {
        return {};
    }

    auto versionIndex = static_cast<size_t>(symbolVersions[symbolIndex] & 0x7fff);

    if (versionIndex < 2 || versionIndex >= versionNames.size()) {
        return {};
    }

    return versionNames[versionIndex];
}

static uint32_t sysvSymbolHash(const std::string_view& name) noexcept {
    uint32_t hash = 0;

    for (unsigned char character : name) {
        hash = (hash << 4) + character;

        auto high = hash & 0xf0000000;

        hash ^= high >> 24;
        hash &= ~high;
    }

    return hash;
}

static uint32_t gnuSymbolHash(const std::string_view& name) noexcept {
    uint32_t hash = 5381;

    for (auto character : name) {
        hash = hash * 33 + static_cast<unsigned char>(character);
    }

    return hash;
}

Definition LinkMap::matchSymbol(size_t index, const std::string_view& name, const std::string_view& version) noexcept {
    auto* symbol = &symbols[index];
    auto foundVersion = symbolVersion(index);
    auto hidden = symbolVersions && (symbolVersions[index] & 0x8000);
    auto versionMatches = version.empty() ? !hidden : foundVersion == version;
    auto visibility = ELF64_ST_VISIBILITY(symbol->st_other);

    if (symbol->st_name < stringsSize && std::string_view(strings + symbol->st_name) == name && symbol->st_shndx != SHN_UNDEF && versionMatches && visibility != STV_HIDDEN && visibility != STV_INTERNAL) {
        return {base + symbol->st_value, this, symbol};
    }

    return {};
}

Definition LinkMap::findSymbol(const std::string_view& name, const std::string_view& version) noexcept {
    if (!gnuHash) {
        // The SysV fallback for images linked with --hash-style=sysv.
        auto bucketCount = sysvHash[0];

        if (!bucketCount) {
            return {};
        }

        auto* buckets = sysvHash + 2;
        auto* chains = buckets + bucketCount;

        for (auto index = buckets[sysvSymbolHash(name) % bucketCount]; index; index = chains[index]) {
            if (auto definition = matchSymbol(index, name, version); definition) {
                return definition;
            }
        }

        return {};
    }

    auto bucketCount = gnuHash[0];
    auto symbolOffset = gnuHash[1];
    auto bloomSize = gnuHash[2];
    auto bloomShift = gnuHash[3];

    if (!bucketCount || !bloomSize) {
        return {};
    }

    auto* bloom = reinterpret_cast<Elf64_Xword*>(gnuHash + 4);
    auto* buckets = reinterpret_cast<uint32_t*>(bloom + bloomSize);
    auto* chains = buckets + bucketCount;
    auto hash = gnuSymbolHash(name);
    constexpr unsigned WORD_BITS = 8 * sizeof(Elf64_Xword);
    auto word = bloom[(hash / WORD_BITS) % bloomSize];
    auto mask = (Elf64_Xword(1) << (hash % WORD_BITS)) | (Elf64_Xword(1) << ((hash >> bloomShift) % WORD_BITS));

    if ((word & mask) != mask) {
        return {};
    }

    auto index = buckets[hash % bucketCount];

    if (index < symbolOffset) {
        return {};
    }

    for (;;) {
        auto chain = chains[index - symbolOffset];

        if ((chain | 1) == (hash | 1)) {
            if (auto definition = matchSymbol(index, name, version); definition) {
                return definition;
            }
        }
        if (chain & 1) {
            break;
        }
        ++index;
    }

    return {};
}

Definition Loader::resolveSymbol(LinkMap& image, size_t symbolIndex) {
    auto* symbol = &image.symbols[symbolIndex];

    // A defined symbol still goes through the scopes — that is what makes an
    // image's own globals interposable, and why its calls use a PLT at all.
    // Only local binding and non-default visibility pin the definition here.
    if (symbol->st_shndx != SHN_UNDEF && (ELF64_ST_BIND(symbol->st_info) == STB_LOCAL || ELF64_ST_VISIBILITY(symbol->st_other) != STV_DEFAULT)) {
        return {image.base + symbol->st_value, &image, symbol};
    }
    if (symbol->st_name >= image.stringsSize) {
        throwError("%s: symbol name outside the string table", image.path.c_str());
    }

    std::string_view name(image.strings + symbol->st_name);
    auto version = image.symbolVersion(symbolIndex);
    auto weak = ELF64_ST_BIND(symbol->st_info) == STB_WEAK;

    if (image.glibcAbi || image.bionicAbi) {
        if (auto* address = resolveGlibcOverride(name, version); address) {
            debugBinding(image, name, "glibc bridge (override)");
            return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
        }
    }

    // ld.so's order: a DT_SYMBOLIC image binds its own definitions first;
    // then the global scope in load order, then the image's own dependency
    // closure — with RTLD_DEEPBIND swapping those two, so interposers in the
    // global scope cannot reach inside the image's closure.
    auto resolve = [&](const std::string_view& wanted) -> Definition {
        if (image.symbolic) {
            if (auto definition = image.findSymbol(name, wanted); definition) {
                return definition;
            }
        }

        auto globally = [&]() -> Definition {
            for (auto* global : globalImages_) {
                if (auto definition = global->findSymbol(name, wanted); definition) {
                    return definition;
                }
            }

            return {};
        };
        auto locally = [&]() {
            return searchScope(image, name, wanted);
        };

        auto definition = image.deepBind ? locally() : globally();

        if (!definition) {
            definition = image.deepBind ? globally() : locally();
        }

        return definition;
    };

    auto definition = resolve(version);

    if (!definition && !version.empty()) {
        // ld.so's compatibility rule: a provider built without any version
        // information satisfies a versioned reference. Only a genuinely
        // unversioned definition qualifies — a wrong-version one stays a
        // loud failure.
        auto compat = resolve({});

        if (compat && compat.image && compat.symbol && compat.image->symbolVersion(compat.symbol - compat.image->symbols).empty()) {
            definition = compat;
        }
    }
    if (definition) {
        debugBinding(image, name, definition.image ? definition.image->path.c_str() : "static provider");
        return definition;
    }

    auto* address = image.glibcAbi   ? resolveGlibcSymbol(name, version, weak)
                    : image.bionicAbi ? resolveBionicSymbol(name, weak)
                                      : nullptr;

    if (!address && !weak) {
        throwError("%s: unresolved symbol %.*s%.*s%.*s", image.path.c_str(), static_cast<int>(name.size()), name.data(), version.empty() ? 0 : 1, "@", static_cast<int>(version.size()), version.data());
    }

    debugBinding(image, name, address ? "glibc bridge" : "weak, unresolved");
    return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
}

void Loader::debugBinding(const LinkMap& image, const std::string_view& name, const char* provider) const {
    if (debugBindings_) {
        fprintf(stderr, "solo: bind %s: %.*s -> %s\n", image.path.c_str(), static_cast<int>(name.size()), name.data(), provider);
    }
}

void* Loader::materialize(Definition definition) {
    if (!definition) {
        return nullptr;
    }
    if (!definition.symbol) {
        return reinterpret_cast<void*>(definition.address);
    }

    auto type = ELF64_ST_TYPE(definition.symbol->st_info);

    if (type == STT_GNU_IFUNC) {
        return reinterpret_cast<void*>(resolveIfunc(definition.address));
    }
    if (type == STT_TLS) {
        uintptr_t index[2] = {
            reinterpret_cast<uintptr_t>(definition.image),
            definition.symbol->st_value,
        };

        return elfTlsAddress(index);
    }

    return reinterpret_cast<void*>(definition.address);
}

void LinkMap::applyRelativeRelocations() {
    uintptr_t* where = nullptr;

    for (size_t index = 0; index < relativeRelocationCount; ++index) {
        auto entry = relativeRelocations[index];

        if (!(entry & 1)) {
            where = reinterpret_cast<uintptr_t*>(base + entry);
            *where += base;
            ++where;
            continue;
        }
        if (!where) {
            throwError("%s: RELR bitmap appears before an address", path.c_str());
        }

        for (unsigned bit = 1; bit < 8 * sizeof(entry); ++bit) {
            if (entry & (uintptr_t(1) << bit)) {
                where[bit - 1] += base;
            }
        }
        where += 8 * sizeof(entry) - 1;
    }
}

bool Loader::applyRelocation(LinkMap& image, const Elf64_Rela& relocation, bool allowIfunc) {
    auto type = ELF64_R_TYPE(relocation.r_info);
    auto symbolIndex = ELF64_R_SYM(relocation.r_info);
    auto* where = reinterpret_cast<uintptr_t*>(image.base + relocation.r_offset);

    if (type == R_ARCH_RELATIVE) {
        *where = image.base + relocation.r_addend;
        return false;
    }
    if (type == R_ARCH_IRELATIVE) {
        if (!allowIfunc) {
            return true;
        }

        *where = resolveIfunc(image.base + relocation.r_addend);
        return false;
    }
    if (!symbolIndex) {
        if (type == R_ARCH_TLS_DTPMOD) {
            if (!image.tlsModule) {
                throwError("%s: local TLS relocation has no module", image.path.c_str());
            }
            *where = reinterpret_cast<uintptr_t>(&image);
            return false;
        }
        if (type == R_ARCH_TLS_DTPREL) {
            *where = relocation.r_addend;
            return false;
        }
        if (type == R_ARCH_TLSDESC) {
            if (!image.tlsModule) {
                throwError("%s: local TLSDESC has no module", image.path.c_str());
            }
            auto* argument = new TlsDescArgument{
                &image,
                static_cast<uintptr_t>(relocation.r_addend),
            };
            where[0] = reinterpret_cast<uintptr_t>(elfTlsDescEntry);
            where[1] = reinterpret_cast<uintptr_t>(argument);
            return false;
        }
        if (type == R_ARCH_TLS_TPREL) {
            if (!image.tlsModule) {
                throwError("%s: local initial-exec relocation has no module", image.path.c_str());
            }
            if (!image.staticTlsOffset) {
                throwError("%s: initial-exec TLS: %zu bytes with %zu-byte alignment did not fit the static TLS arena (%zu of %zu bytes in use)", image.path.c_str(), image.tlsMemorySize, image.tlsAlignment, staticTlsUsed_, staticTlsSize);
            }
            *where = static_cast<uintptr_t>(image.staticTlsOffset) + relocation.r_addend;
            return false;
        }
    }

    auto definition = resolveSymbol(image, symbolIndex);
    auto weak = ELF64_ST_BIND(image.symbols[symbolIndex].st_info) == STB_WEAK;

    if (!definition && !weak) {
        throwError("%s: unresolved relocation symbol", image.path.c_str());
    }

    auto ifunc = definition.symbol && ELF64_ST_TYPE(definition.symbol->st_info) == STT_GNU_IFUNC;

    if (ifunc && !allowIfunc) {
        return true;
    }
    if (ifunc) {
        definition.address = resolveIfunc(definition.address);
    }

    switch (type) {
        case R_ARCH_ABS64:
            *where = definition.address + relocation.r_addend;
            return false;
        case R_ARCH_GLOB_DAT:
        case R_ARCH_JUMP_SLOT:
            *where = definition.address;
            return false;
        case R_ARCH_TLS_DTPMOD:
            if (!symbolIndex) {
                definition.image = &image;
            }
            if (!definition.image || !definition.image->tlsModule) {
                throwError("%s: TLS module relocation has no ELF TLS provider", image.path.c_str());
            }
            *where = reinterpret_cast<uintptr_t>(definition.image);
            return false;
        case R_ARCH_TLS_DTPREL:
            if (!symbolIndex) {
                *where = relocation.r_addend;
                return false;
            }
            if (!definition.image || !definition.symbol || !definition.image->tlsModule) {
                throwError("%s: TLS offset relocation has no ELF TLS provider", image.path.c_str());
            }
            *where = definition.symbol->st_value + relocation.r_addend;
            return false;
        case R_ARCH_TLSDESC: {
            uintptr_t offset = relocation.r_addend;

            if (!symbolIndex) {
                definition.image = &image;
            } else if (definition.symbol) {
                offset += definition.symbol->st_value;
            }
            if (!definition.image || !definition.image->tlsModule) {
                throwError("%s: TLSDESC has no ELF TLS provider", image.path.c_str());
            }

            auto* argument = new TlsDescArgument{
                definition.image,
                offset,
            };
            where[0] = reinterpret_cast<uintptr_t>(elfTlsDescEntry);
            where[1] = reinterpret_cast<uintptr_t>(argument);
            return false;
        }
        case R_ARCH_TLS_TPREL: {
            if (!definition) {
                *where = 0;
                return false;
            }
            if (!definition.image || !definition.symbol || !definition.image->tlsModule) {
                throwError("%s: initial-exec relocation has no ELF TLS provider", image.path.c_str());
            }

            const auto& provider = *definition.image;

            if (!provider.staticTlsOffset) {
                throwError("%s: initial-exec TLS against %s: %zu bytes with %zu-byte alignment did not fit the static TLS arena (%zu of %zu bytes in use)", image.path.c_str(), provider.path.c_str(), provider.tlsMemorySize, provider.tlsAlignment, staticTlsUsed_, staticTlsSize);
            }
            *where = static_cast<uintptr_t>(provider.staticTlsOffset) + definition.symbol->st_value + relocation.r_addend;
            return false;
        }
        default:
            throwError("%s: unsupported relocation type %u at %#lx", image.path.c_str(), type, static_cast<unsigned long>(relocation.r_offset));
    }
}

void Loader::applyRelocations(LinkMap& image, std::vector<DeferredRelocation>& deferred, bool lazy) {
    image.applyRelativeRelocations();

    for (size_t index = 0; index < image.relocationCount; ++index) {
        if (applyRelocation(image, image.relocations[index], false)) {
            deferred.push_back({&image, &image.relocations[index]});
        }
    }

    lazy = lazy && image.pltGot;

    for (size_t index = 0; index < image.pltRelocationCount; ++index) {
        const auto& relocation = image.pltRelocations[index];

        // A lazy JUMP_SLOT keeps pointing at its PLT push, rebased; the first
        // call enters elfPltResolveEntry through PLT0.
        if (lazy && ELF64_R_TYPE(relocation.r_info) == R_ARCH_JUMP_SLOT) {
            *reinterpret_cast<uintptr_t*>(image.base + relocation.r_offset) += image.base;
            continue;
        }
        if (applyRelocation(image, relocation, false)) {
            deferred.push_back({&image, &relocation});
        }
    }

    if (lazy) {
        auto* got = reinterpret_cast<uintptr_t*>(image.pltGot);

        got[1] = reinterpret_cast<uintptr_t>(&image);
        got[2] = reinterpret_cast<uintptr_t>(elfPltResolveEntry);
    }
}

void* Loader::pltResolve(LinkMap& image, size_t index) {
    std::lock_guard lock(mutex_);

    if (index >= image.pltRelocationCount) {
        throwError("%s: PLT relocation %zu out of range", image.path.c_str(), index);
    }

    const auto& relocation = image.pltRelocations[index];

    applyRelocation(image, relocation, true);

    return *reinterpret_cast<void**>(image.base + relocation.r_offset);
}

void LinkMap::protect() {
    auto pageSize = sysconf(_SC_PAGESIZE);

    if (pageSize <= 0 || mprotect(reinterpret_cast<void*>(mapStart), mapSize, PROT_NONE)) {
        throwError("%s: mprotect(PROT_NONE): %s", path.c_str(), strerror(errno));
    }

    for (const auto& programHeader : programHeaders) {
        if (programHeader.p_type != PT_LOAD) {
            continue;
        }

        auto start = alignDown(base + programHeader.p_vaddr, pageSize);
        auto end = alignUp(base + programHeader.p_vaddr + programHeader.p_memsz, pageSize);

        if (mprotect(reinterpret_cast<void*>(start), end - start, segmentProtection(programHeader.p_flags))) {
            throwError("%s: mprotect(PT_LOAD): %s", path.c_str(), strerror(errno));
        }
    }
}

void LinkMap::applyRelro() {
    if (!relroSize) {
        return;
    }

    auto pageSize = sysconf(_SC_PAGESIZE);
    auto start = alignDown(base + relroStart, pageSize);
    auto end = alignUp(base + relroStart + relroSize, pageSize);

    if (mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ)) {
        throwError("%s: mprotect(RELRO): %s", path.c_str(), strerror(errno));
    }
}

void LinkMap::runInitializers() {
    if (initializer) {
        reinterpret_cast<void (*)()>(initializer)();
    }

    auto* initializers = reinterpret_cast<uintptr_t*>(initializerArray);

    for (size_t index = 0; index < initializerCount; ++index) {
        if (initializers[index] && initializers[index] != UINTPTR_MAX) {
            reinterpret_cast<void (*)()>(initializers[index])();
        }
    }
}

void LinkMap::runFinalizers() {
    auto* finalizers = reinterpret_cast<uintptr_t*>(finalizerArray);

    for (size_t index = finalizerCount; index; --index) {
        if (finalizers[index - 1] && finalizers[index - 1] != UINTPTR_MAX) {
            reinterpret_cast<void (*)()>(finalizers[index - 1])();
        }
    }
    if (finalizer) {
        reinterpret_cast<void (*)()>(finalizer)();
    }
}

void Loader::runAllFinalizers() {
    std::vector<LinkMap*> images;
    {
        auto& loader = instance();
        std::lock_guard lock(loader.mutex_);

        images.reserve(loader.images_.size());
        for (const auto& image : loader.images_) {
            if (image->state == LinkMap::State::Ready) {
                images.push_back(image.get());
            }
        }
    }

    for (auto image = images.rbegin(); image != images.rend(); ++image) {
        (*image)->runFinalizers();
    }
}

LoadedElf::LoadedElf(LinkMap& image)
    : image_(image)
{
}

void* LoadedElf::lookup(std::string_view symbol) const {
    return Loader::instance().lookup(image_, symbol, {});
}

void* LoadedElf::lookupVersion(std::string_view symbol, std::string_view version) const {
    return Loader::instance().lookup(image_, symbol, version);
}

std::string_view LoadedElf::path() const {
    return image_.path;
}

uintptr_t LoadedElf::base() const {
    return image_.base;
}

const void* LoadedElf::dynamicSection() const {
    return image_.dynamic;
}

ElfImage::~ElfImage() noexcept {
}

IfaceHandle::Kind ElfImage::handleKind() const {
    return kind;
}

ElfImage* ElfImage::loadElf(std::string_view path, int flags) {
    auto& loader = Loader::instance();
    auto* image = loader.load(path, flags);

    loader.runPendingInitializers();

    return image ? image->wrapper.get() : nullptr;
}

bool ElfImage::findAddress(const void* address, ElfAddress* res) {
    return Loader::instance().findAddress(address, res);
}

int ElfImage::iterateProgramHeaders(ElfProgramHeaderCallback& callback) {
    return Loader::instance().iterateProgramHeaders(callback);
}

void* ElfImage::lookupGlobal(std::string_view symbol) {
    return Loader::instance().lookupGlobal(symbol);
}

void* ElfImage::lookupNext(const void* caller, std::string_view symbol, std::string_view version) {
    return Loader::instance().lookupNext(caller, symbol, version);
}

// The C half of the lazy binder: called from elfPltResolveEntry with the
// caller's registers saved. A resolution failure cannot unwind through the
// PLT frames, so it aborts with the loader's error instead.
extern "C" void* elfPltResolve(void* image, uint64_t index) {
    try {
        return Loader::instance().pltResolve(*static_cast<LinkMap*>(image), index);
    } catch (const std::exception& error) {
        fprintf(stderr, "solo: lazy binding failed: %s\n", error.what());
    } catch (...) {
        fprintf(stderr, "solo: lazy binding failed\n");
    }
    abort();
}

extern "C" void* elfTlsAddress(const uintptr_t index[2]) {
    return reinterpret_cast<const LinkMap*>(index[0])->tlsAddress(index[1]);
}

extern "C" void* elfTlsDescAddress(const void* opaqueArgument) {
    const auto& argument = *static_cast<const TlsDescArgument*>(opaqueArgument);

    return argument.image->tlsAddress(argument.offset);
}
