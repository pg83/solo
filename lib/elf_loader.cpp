#include "elf_loader.h"

#include "dlfcn.h"
#include "bionic_shim.h"
#include "glibc_shim.h"
#include "musl_tls.h"
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

#ifndef MAP_FIXED_NOREPLACE
    #define MAP_FIXED_NOREPLACE 0x100000
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
    #define R_ARCH_COPY 5
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
    #define R_ARCH_COPY 1024
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
        // The image's slot in the dlopen caller-thunk pool, assigned on the
        // first relocation of its dlopen or dlmopen import.
        int callerThunkIndex = -1;

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

        // The main guest executable: its entry point and mapped program
        // headers feed the auxiliary vector, and its initializers wait for
        // the bridge's __libc_start_main instead of the load-time queue.
        bool executable = false;
        uintptr_t entry = 0;
        uintptr_t programHeadersAddress = 0;

        uintptr_t preinitializerArray = 0;
        size_t preinitializerCount = 0;
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
        // TLS window: negative on x86-64 (TLS below the thread pointer),
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

        LinkMap* load(const std::string_view& requestedPath, int flags, LinkMap* dlopenCaller);
        LinkMap* adopt(const char* path, const Elf64_Phdr* headers, size_t count, uintptr_t entry);
        void linkImage(LinkMap& image, int flags, bool adopted);
        void runPendingInitializers();

        void* lookup(LinkMap& image, std::string_view name, std::string_view version);
        void* lookupGlobal(std::string_view name);
        void* lookupNext(const void* caller, std::string_view name, std::string_view version);
        void makeGlobal(LinkMap& image);

        bool findAddress(const void* address, ElfAddress* res);
        int iterateProgramHeaders(ElfProgramHeaderCallback& callback);

        void* callerThunk(LinkMap& image, bool dlmopen);
        LinkMap* callerImage(unsigned index);

        LinkMap* findByName(const std::string_view& name) const noexcept;
        LinkMap* findByPath(const std::string& path) const noexcept;

        static std::optional<std::string> realPath(const std::string& path);
        static std::optional<std::string> inDirectory(const std::string_view& directory, const std::string_view& name);
        static std::optional<std::string> inSearchPath(std::string_view directories, const std::string_view& name, bool emptyIsCurrentDirectory);
        static std::optional<std::string> inCache(const std::string_view& name);

        std::optional<std::string> resolvePath(const std::string_view& path, const LinkMap* dlopenCaller) const;
        void rememberLibraryDirectory(const std::string& path);

        size_t addTlsModule();
        void allocateStaticTls(LinkMap& image);
        void seedStaticTls(LinkMap& image);

        static bool isGlibcDependency(const std::string_view& name) noexcept;
        void loadDependencies(LinkMap& image);

        static Definition searchScope(LinkMap& image, const std::string_view& name, const std::string_view& version, bool skipSelf);
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
        std::string libraryDirectory_;
        LinkMap* requester_ = nullptr;
        // Consumed by the next load(): it is loading the main guest
        // executable, not a shared object.
        bool loadingExecutable_ = false;
        LinkMap* mainExecutable_ = nullptr;
        std::vector<LinkMap*> pendingInitializers_;
        bool bindNow_ = false;
        bool debugLibs_ = false;
        bool debugBindings_ = false;
        // Images whose symbols every later relocation may use, in load order.
        std::vector<LinkMap*> globalImages_;
        // The images behind the numbered dlopen caller thunks; write-once
        // slots, published before the thunk address escapes.
        std::array<LinkMap*, 512> callerImages_{};
        size_t callerCount_ = 0;
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

bool dyn::secureExecution() {
    static const bool secure = [] {
        errno = 0;
        if (getauxval(AT_SECURE)) {
            return true;
        }
        if (errno != ENOENT) {
            // The auxv answered: the kernel says not secure.
            return false;
        }

        return getuid() != geteuid() || getgid() != getegid();
    }();

    return secure;
}

bool dyn::traceLoadedObjects() {
    static const bool enabled = !secureExecution() && getenv("LD_TRACE_LOADED_OBJECTS");

    return enabled;
}

// Each provided name prints once, like ldd's one line per object; callers
// arrive both under the loader mutex and outside it.
void dyn::traceProvider(std::string_view name, const char* provider) {
    static std::mutex tracedMutex;
    static std::unordered_set<std::string> traced;

    if (!traceLoadedObjects()) {
        return;
    }

    std::lock_guard lock(tracedMutex);

    if (traced.emplace(name).second) {
        fprintf(stdout, "\t%.*s => %s\n", static_cast<int>(name.size()), name.data(), provider);
    }
}

bool dyn::debugFlag(std::string_view flag) {
    static const std::string flags = [] {
        const auto* debug = secureExecution() ? nullptr : getenv("LD_DEBUG");

        return std::string(debug ? debug : "");
    }();

    std::string_view remaining(flags);

    while (!remaining.empty()) {
        auto comma = remaining.find(',');
        auto entry = remaining.substr(0, comma);

        remaining.remove_prefix(comma == std::string_view::npos ? remaining.size() : comma + 1);
        if (entry == flag || entry == "all") {
            return true;
        }
    }

    return false;
}

// Registered before any loaded DSO can register its own atexit handlers, so
// like glibc's _dl_fini it runs after them.
Loader::Loader() {
    bindNow_ = getenv("LD_BIND_NOW") != nullptr;
    debugLibs_ = debugFlag("libs");
    debugBindings_ = debugFlag("bindings");
    atexit(runAllFinalizers);
}

Loader& Loader::instance() {
    static auto* loader = new Loader();

    return *loader;
}

LinkMap* Loader::load(const std::string_view& requestedPath, int flags, LinkMap* dlopenCaller) {
    std::lock_guard lock(mutex_);

    // The flag names only the outermost load; the dependencies this load
    // pulls in are ordinary shared objects.
    auto asExecutable = std::exchange(loadingExecutable_, false);

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

    auto resolved = resolvePath(requestedPath, dlopenCaller);

    if (!resolved) {
        traceProvider(requestedPath, "not found");
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

    // Shared objects are ET_DYN; the main guest executable may equally be a
    // non-PIE ET_EXEC, which owns its link-time addresses.
    auto validType = header.e_type == ET_DYN || (asExecutable && header.e_type == ET_EXEC);

    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != ELF_MACHINE || !validType || header.e_phentsize != sizeof(Elf64_Phdr)) {
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
    // the file below. An ET_EXEC image must land exactly on its link-time
    // addresses, and an occupied range there is a hard error — nothing can
    // relocate it. This is why solo itself links static-PIE: its own image
    // randomizes away from the low addresses such guests own.
    auto* desired = header.e_type == ET_EXEC ? reinterpret_cast<void*>(minimumAddress) : nullptr;
    auto* mapping = mmap(desired, image.mapSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | (desired ? MAP_FIXED_NOREPLACE : 0), -1, 0);

    if (mapping == MAP_FAILED) {
        throwError("%s: mmap%s: %s", image.path.c_str(), desired ? " at the fixed load addresses" : "", strerror(errno));
    }
    // A kernel too old for MAP_FIXED_NOREPLACE ignores the flag and treats
    // the address as a hint; a reservation that landed elsewhere is as fatal
    // as a refused one.
    if (desired && mapping != desired) {
        munmap(mapping, image.mapSize);
        throwError("%s: the fixed load addresses %#zx-%#zx are already occupied", image.path.c_str(), minimumAddress, maximumAddress);
    }

    image.mapStart = reinterpret_cast<uintptr_t>(mapping);
    image.base = image.mapStart - minimumAddress;

    auto* imagePointer = &image;
    images_.push_back(std::move(imageOwner));
    imagesByName_.emplace(image.path, &image);
    imagesByName_.emplace(std::string(requestedPath), &image);
    imagesByAddress_.emplace(image.mapStart, &image);

    // ldd lists the objects an executable pulls in, never the executable
    // itself.
    if (traceLoadedObjects() && !asExecutable) {
        fprintf(stdout, "\t%.*s => %s (0x%zx)\n", static_cast<int>(requestedPath.size()), requestedPath.data(), image.path.c_str(), image.mapStart);
    }

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

    if (asExecutable) {
        image.executable = true;
        image.entry = image.base + header.e_entry;
        // What the kernel would publish as AT_PHDR: the program header table
        // inside the mapped image, by PT_PHDR when the link editor recorded
        // one, by the ELF header's table offset otherwise.
        image.programHeadersAddress = image.base + header.e_phoff;
        for (const auto& programHeader : image.programHeaders) {
            if (programHeader.p_type == PT_PHDR) {
                image.programHeadersAddress = image.base + programHeader.p_vaddr;
            }
        }
    }

    linkImage(image, flags, false);

    return imagePointer;
}

// The guest the kernel already mapped, solo running as its PT_INTERP: the
// auxiliary vector's program headers, entry point, and execution path stand
// in for the file. The segments are in place with their final protections;
// everything after the mapping is the same back half a loaded image takes.
LinkMap* Loader::adopt(const char* path, const Elf64_Phdr* headers, size_t count, uintptr_t entry) {
    std::lock_guard lock(mutex_);

    if (!headers || !count) {
        throwError("the auxiliary vector describes no program headers to adopt");
    }

    auto imageOwner = std::make_unique<LinkMap>();
    auto& image = *imageOwner;

    image.path = realPath(path).value_or(path);
    rememberLibraryDirectory(image.path);

    // The load bias, anchored by PT_PHDR: the table's runtime address is in
    // hand, and the entry names its link-time one. Every dynamically linked
    // executable carries the entry — the link editor emits it alongside
    // PT_INTERP, and only a guest with an interpreter can arrive here.
    auto biasKnown = false;

    image.programHeaders.assign(headers, headers + count);
    for (const auto& programHeader : image.programHeaders) {
        if (programHeader.p_type == PT_PHDR) {
            image.base = reinterpret_cast<uintptr_t>(headers) - programHeader.p_vaddr;
            biasKnown = true;
        }
    }
    if (!biasKnown) {
        throwError("%s: the kernel-mapped executable has no PT_PHDR to anchor its load base", image.path.c_str());
    }

    auto pageSize = sysconf(_SC_PAGESIZE);

    if (pageSize <= 0) {
        throwError("%s: cannot determine page size", image.path.c_str());
    }

    uintptr_t minimumAddress = UINTPTR_MAX;
    uintptr_t maximumAddress = 0;

    for (const auto& programHeader : image.programHeaders) {
        if (programHeader.p_type == PT_LOAD) {
            minimumAddress = std::min(minimumAddress, alignDown(programHeader.p_vaddr, pageSize));
            maximumAddress = std::max(maximumAddress, alignUp(programHeader.p_vaddr + programHeader.p_memsz, pageSize));
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
    if (minimumAddress == UINTPTR_MAX || maximumAddress <= minimumAddress) {
        throwError("%s: no loadable segments", image.path.c_str());
    }

    image.mapStart = image.base + minimumAddress;
    image.mapSize = maximumAddress - minimumAddress;
    image.executable = true;
    image.entry = entry;
    image.programHeadersAddress = reinterpret_cast<uintptr_t>(headers);

    auto* imagePointer = &image;
    images_.push_back(std::move(imageOwner));
    imagesByName_.emplace(image.path, &image);
    imagesByName_.emplace(std::string(path), &image);
    imagesByAddress_.emplace(image.mapStart, &image);

    MarkFailed markFailed(image);

    linkImage(image, RTLD_GLOBAL, true);

    return imagePointer;
}

// The back half every image goes through, mapped by us or adopted from the
// kernel: dependencies, relocations, protections, TLS, and the initializer
// queue. An adopted image keeps the kernel's segment protections — they are
// already final — but RELRO stays ours to seal; the kernel never applies it.
void Loader::linkImage(LinkMap& image, int flags, bool adopted) {
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
    if (!adopted) {
        image.protect();
    }

    for (const auto& item : deferred) {
        applyRelocation(*item.image, *item.relocation, true);
    }
    image.applyRelro();
    if (image.tlsModule) {
        seedStaticTls(image);
    }

    image.wrapper.reset(new LoadedElf(image));
    image.state = LinkMap::State::Ready;
    if (image.executable) {
        mainExecutable_ = &image;
    }
    if (flags & RTLD_GLOBAL) {
        makeGlobal(image);
    }
    if (debugLibs_) {
        fprintf(stderr, "solo: loaded %s at %#lx%s\n", image.path.c_str(), image.base, lazy ? " (lazy)" : "");
    }
    pendingInitializers_.push_back(&image);
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

    return materialize(searchScope(image, name, version, false));
}

// Breadth-first over the image and its dependency closure, in load order at
// each depth, matching the search order of ld.so. A dependency backed by a
// static provider is probed at its depth through its handle.
Definition Loader::searchScope(LinkMap& image, const std::string_view& name, const std::string_view& version, bool skipSelf) {
    // glibc's COPY discipline searches everything but the requesting image:
    // its own symbol table holds the copy's destination, not a definition.
    if (!skipSelf) {
        if (auto definition = image.findSymbol(name, version); definition) {
            return definition;
        }
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

    // A module placed in the static window must be served from it through
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

void* Loader::callerThunk(LinkMap& image, bool dlmopen) {
    if (image.callerThunkIndex < 0) {
        auto* probe = glibcDlopenCaller(callerCount_);

        if (!probe) {
            throwError("%s: the dlopen caller pool is exhausted", image.path.c_str());
        }
        image.callerThunkIndex = static_cast<int>(callerCount_);
        // Written before the caller's address reaches any GOT slot; the
        // loader mutex is held through both.
        callerImages_[callerCount_++] = &image;
    }

    auto index = static_cast<unsigned>(image.callerThunkIndex);

    return dlmopen ? glibcDlmopenCaller(index) : glibcDlopenCaller(index);
}

LinkMap* Loader::callerImage(unsigned index) {
    return index < callerImages_.size() ? callerImages_[index] : nullptr;
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

std::optional<std::string> Loader::resolvePath(const std::string_view& path, const LinkMap* dlopenCaller) const {
    if (path.find('/') != std::string_view::npos) {
        return realPath(std::string(path));
    }

    // A dlopen issued by loaded code searches the calling image's paths;
    // while resolving DT_NEEDED, the image being loaded is the requester.
    const LinkMap* requester = dlopenCaller ? dlopenCaller : requester_;

    // ld.so's AT_SECURE discipline: a privileged process must not search
    // paths the environment names.
    const bool secure = secureExecution();
    if (requester && !requester->rpath.empty()) {
        if (auto resolved = inSearchPath(requester->rpath, path, false); resolved) {
            return resolved;
        }
    }
    if (const auto* configured = secure ? nullptr : getenv("LD_LIBRARY_PATH"); configured) {
        if (auto resolved = inSearchPath(configured, path, true); resolved) {
            return resolved;
        }
    }
    if (requester && !requester->runPath.empty()) {
        if (auto resolved = inSearchPath(requester->runPath, path, false); resolved) {
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

// Places a freshly loaded module's TLS in the static TLS pad, making one
// thread-pointer-relative offset valid in every thread at once, which is
// what initial-exec relocations demand. On overflow the module falls back to
// the dynamic per-thread blocks, and only a later initial-exec reference to
// it fails. The main guest executable instead takes the ABI slot adjacent to
// the thread pointer, where the offsets its static linker burned into
// local-exec instructions point — and there is no fallback.
void Loader::allocateStaticTls(LinkMap& image) {
    image.staticTlsOffset = image.executable
        ? soloExecutableTls(reinterpret_cast<const void*>(image.tlsTemplate), image.tlsMemorySize, image.tlsAlignment)
        : soloStaticTls(image.tlsMemorySize, image.tlsAlignment);

    if (image.executable && !image.staticTlsOffset) {
        throwError("%s: the executable's TLS (%zu bytes, %zu-byte alignment) cannot take the ABI slot next to the thread pointer; a stray thread_local unseated the pad, an executable is already placed, or the block does not fit alongside the loaded libraries", image.path.c_str(), image.tlsMemorySize, image.tlsAlignment);
    }
}

// The loading thread's own copy of a placed block, seeded after relocations
// so relocated template bytes land in it — and only then registered with
// musl, so threads created later are seeded from relocated bytes too.
// Threads already running keep zeroes, like ld.so: dlopen libraries with TLS
// before spawning threads that use them.
void Loader::seedStaticTls(LinkMap& image) {
    if (!image.staticTlsOffset) {
        return;
    }

    auto* block = reinterpret_cast<unsigned char*>(threadPointer() + image.staticTlsOffset);

    memset(block, 0, image.tlsMemorySize);
    memcpy(block, reinterpret_cast<const void*>(image.tlsTemplate), image.tlsFileSize);
    soloTlsRegister(reinterpret_cast<const void*>(image.tlsTemplate), image.tlsFileSize, image.tlsMemorySize, image.staticTlsOffset);
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
            traceProvider(needed, "the glibc ABI bridge over the embedded musl");
            image.glibcAbi = true;
            continue;
        }
        if (isBionicDependency(needed)) {
            traceProvider(needed, "the bionic ABI bridge over the embedded musl");
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
            case DT_PREINIT_ARRAY:
                preinitializerArray = base + entry->d_un.d_ptr;
                break;
            case DT_PREINIT_ARRAYSZ:
                preinitializerCount = entry->d_un.d_val / sizeof(uintptr_t);
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
        auto colon = directories.find(':');
        auto entry = directories.substr(0, colon);

        directories.remove_prefix(colon == std::string_view::npos ? directories.size() : colon + 1);
        // ld.so's AT_SECURE discipline, musl's rule: a privileged process
        // drops search entries carrying dynamic string tokens, whose
        // expansion the invoker can influence.
        if (secureExecution() && entry.find('$') != std::string_view::npos) {
            continue;
        }
        if (!result.empty()) {
            result.push_back(':');
        }
        while (!entry.empty()) {
            auto dollar = entry.find('$');

            if (dollar == std::string_view::npos) {
                result.append(entry);
                break;
            }
            result.append(entry.substr(0, dollar));
            entry.remove_prefix(dollar);
            if (entry.starts_with("${ORIGIN}")) {
                result.append(origin);
                entry.remove_prefix(9);
            } else if (entry.starts_with("$ORIGIN")) {
                result.append(origin);
                entry.remove_prefix(7);
            } else {
                result.push_back('$');
                entry.remove_prefix(1);
            }
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
        // Caller attribution, fixed at relocation time: this image's dlopen
        // and dlmopen must search its own DT_RPATH/DT_RUNPATH, and here the
        // image is known — no stack inspection, correct even when the guest
        // tail-calls dlopen, where a return address would name the caller's
        // caller.
        if ((name == "dlopen" || name == "dlmopen") && (version.empty() || resolveGlibcOverride(name, version))) {
            debugBinding(image, name, "glibc bridge (caller)");
            return {reinterpret_cast<uintptr_t>(callerThunk(image, name == "dlmopen")), nullptr, nullptr};
        }
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
            return searchScope(image, name, wanted, false);
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
                throwError("%s: initial-exec TLS: %zu bytes with %zu-byte alignment did not fit the static TLS window", image.path.c_str(), image.tlsMemorySize, image.tlsAlignment);
            }
            *where = static_cast<uintptr_t>(image.staticTlsOffset) + relocation.r_addend;
            return false;
        }
    }

    if (type == R_ARCH_COPY) {
        // The executable reserved writable storage for a dependency's data
        // object; the definition is taken from anywhere but the executable
        // itself, whose own symbol table names the copy's destination.
        auto* symbol = &image.symbols[symbolIndex];

        if (symbol->st_name >= image.stringsSize) {
            throwError("%s: symbol name outside the string table", image.path.c_str());
        }

        std::string_view name(image.strings + symbol->st_name);
        auto version = image.symbolVersion(symbolIndex);
        auto* source = materialize(searchScope(image, name, version, true));

        if (!source) {
            source = image.glibcAbi    ? resolveGlibcSymbol(name, version, false)
                     : image.bionicAbi ? resolveBionicSymbol(name, false)
                                       : nullptr;
        }
        if (!source) {
            throwError("%s: unresolved copy relocation %.*s", image.path.c_str(), static_cast<int>(name.size()), name.data());
        }
        memcpy(where, source, symbol->st_size);
        return false;
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
                throwError("%s: initial-exec TLS against %s: %zu bytes with %zu-byte alignment did not fit the static TLS window", image.path.c_str(), provider.path.c_str(), provider.tlsMemorySize, provider.tlsAlignment);
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
    // The main executable's initializers run under __libc_start_main with
    // the real argc/argv/envp, after every dependency's; see
    // dyn::runExecutableInitializers.
    if (executable) {
        return;
    }
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
    auto* image = loader.load(path, flags, nullptr);

    loader.runPendingInitializers();

    return image ? image->wrapper.get() : nullptr;
}

ElfExecutable dyn::loadExecutable(std::string_view path) {
    auto& loader = Loader::instance();
    LinkMap* image = nullptr;
    {
        std::lock_guard lock(loader.mutex_);

        loader.loadingExecutable_ = true;
        image = loader.load(path, RTLD_GLOBAL, nullptr);
    }
    // Under LD_TRACE_LOADED_OBJECTS nothing runs, like ld.so's trace mode:
    // the closure is mapped and printed, and the caller exits.
    if (!traceLoadedObjects()) {
        loader.runPendingInitializers();
    }

    return {
        image->entry,
        image->programHeadersAddress,
        image->programHeaders.size(),
        image->base,
    };
}

ElfExecutable dyn::adoptExecutable(const char* path, const Elf64_Phdr* headers, size_t count, uintptr_t entry) {
    auto& loader = Loader::instance();
    auto* image = loader.adopt(path, headers, count, entry);

    if (!traceLoadedObjects()) {
        loader.runPendingInitializers();
    }

    return {
        image->entry,
        image->programHeadersAddress,
        image->programHeaders.size(),
        image->base,
    };
}

void dyn::runExecutableInitializers(int argc, char** argv, char** envp) {
    auto* image = Loader::instance().mainExecutable_;

    if (!image) {
        return;
    }

    using Initializer = void (*)(int, char**, char**);
    auto* preinitializers = reinterpret_cast<uintptr_t*>(image->preinitializerArray);

    for (size_t index = 0; index < image->preinitializerCount; ++index) {
        if (preinitializers[index] && preinitializers[index] != UINTPTR_MAX) {
            reinterpret_cast<Initializer>(preinitializers[index])(argc, argv, envp);
        }
    }
    if (image->initializer) {
        reinterpret_cast<Initializer>(image->initializer)(argc, argv, envp);
    }

    auto* initializers = reinterpret_cast<uintptr_t*>(image->initializerArray);

    for (size_t index = 0; index < image->initializerCount; ++index) {
        if (initializers[index] && initializers[index] != UINTPTR_MAX) {
            reinterpret_cast<Initializer>(initializers[index])(argc, argv, envp);
        }
    }
}

ElfImage* ElfImage::loadElfForCaller(unsigned callerIndex, std::string_view path, int flags) {
    auto& loader = Loader::instance();
    auto* image = loader.load(path, flags, loader.callerImage(callerIndex));

    loader.runPendingInitializers();

    return image ? image->wrapper.get() : nullptr;
}

bool ElfImage::findAddress(const void* address, ElfAddress* res) {
    return Loader::instance().findAddress(address, res);
}

int ElfImage::iterateProgramHeaders(ElfProgramHeaderCallback& callback) {
    return Loader::instance().iterateProgramHeaders(callback);
}

// The linker places __ehdr_start on the executable's ELF header whenever a
// loaded segment covers it. Weak, so a layout that leaves the header unmapped
// resolves it to null instead of failing the link.
extern "C" const unsigned char __ehdr_start[] __attribute__((weak));

ElfMainProgram dyn::elfMainProgram() {
    ElfMainProgram program;

    program.headers = reinterpret_cast<const Elf64_Phdr*>(getauxval(AT_PHDR));
    program.count = static_cast<Elf64_Half>(getauxval(AT_PHNUM));

    const auto* mapped = reinterpret_cast<const Elf64_Ehdr*>(__ehdr_start);

    if (!mapped || memcmp(mapped->e_ident, ELFMAG, SELFMAG) != 0) {
        mapped = nullptr;
    }
    // proot-style loaders build the auxiliary vector by hand and can leave
    // AT_PHDR empty; the executable's own mapped ELF header does not depend
    // on the loading environment at all.
    if (!program.headers || !program.count) {
        if (!mapped) {
            return {};
        }
        program.headers = reinterpret_cast<const Elf64_Phdr*>(__ehdr_start + mapped->e_phoff);
        program.count = mapped->e_phnum;
    }

    bool viaPhdrEntry = false;

    for (Elf64_Half index = 0; index < program.count; ++index) {
        if (program.headers[index].p_type == PT_PHDR) {
            program.base = reinterpret_cast<uintptr_t>(program.headers) - program.headers[index].p_vaddr;
            viaPhdrEntry = true;
        }
    }
    // Without a PT_PHDR entry the mapped ELF header anchors the base itself:
    // it is the byte at file offset zero of the segment that maps it.
    if (!viaPhdrEntry && mapped) {
        for (Elf64_Half index = 0; index < program.count; ++index) {
            const auto& header = program.headers[index];

            if (header.p_type == PT_LOAD && !header.p_offset) {
                program.base = reinterpret_cast<uintptr_t>(mapped) - header.p_vaddr;
            }
        }
    }

    // In interpreter mode the auxiliary vector's main program is the adopted
    // guest, already walked with the loader's images.
    {
        auto& loader = Loader::instance();
        std::lock_guard lock(loader.mutex_);

        program.adopted = loader.mainExecutable_ && loader.mainExecutable_->programHeadersAddress == reinterpret_cast<uintptr_t>(program.headers);
    }

    return program;
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
