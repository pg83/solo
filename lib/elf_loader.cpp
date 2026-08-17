#include "elf_loader.h"

#include "dlfcn.h"
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
#include <sys/mman.h>
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

#ifndef R_X86_64_IRELATIVE
    #define R_X86_64_IRELATIVE 37
#endif

#ifndef R_X86_64_TLSDESC
    #define R_X86_64_TLSDESC 36
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
        Elf64_Half* symbolVersions = nullptr;
        std::vector<std::string_view> versionNames;
        std::vector<Dependency> dependencies;
        bool glibcAbi = false;

        Elf64_Rela* relocations = nullptr;
        size_t relocationCount = 0;
        Elf64_Rela* pltRelocations = nullptr;
        size_t pltRelocationCount = 0;
        Elf64_Addr* relativeRelocations = nullptr;
        size_t relativeRelocationCount = 0;

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

        std::unique_ptr<ElfImage> wrapper;

        State state = State::Loading;

        void parseDynamic();
        void parseVersions(uintptr_t needAddress, size_t needCount, uintptr_t definitionAddress, size_t definitionCount);
        void setVersionName(size_t index, size_t nameOffset);
        size_t countSymbols() const noexcept;
        std::string substituteOrigin(std::string_view directories) const;
        std::string_view symbolVersion(size_t symbolIndex) const noexcept;
        Definition findSymbol(const std::string_view& name, const std::string_view& version) noexcept;
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

    struct Loader {
        Loader();

        static Loader& instance();

        LinkMap* load(const std::string_view& requestedPath, int flags);

        void* lookup(LinkMap& image, std::string_view name);
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

        std::optional<std::string> resolvePath(const std::string_view& path) const;
        void rememberLibraryDirectory(const std::string& path);

        size_t addTlsModule();

        static bool isGlibcDependency(const std::string_view& name) noexcept;
        void loadDependencies(LinkMap& image);

        static Definition searchScope(LinkMap& image, const std::string_view& name, const std::string_view& version);
        Definition resolveSymbol(LinkMap& image, size_t symbolIndex);
        static void* materialize(Definition definition);

        bool applyRelocation(LinkMap& image, const Elf64_Rela& relocation, bool allowIfunc);
        void applyRelocations(LinkMap& image, std::vector<DeferredRelocation>& deferred);
        static void runAllFinalizers();

        std::recursive_mutex mutex_;
        std::vector<std::unique_ptr<LinkMap>> images_;
        std::unordered_map<std::string, LinkMap*, StringHash, std::equal_to<>> imagesByName_;
        std::map<uintptr_t, LinkMap*> imagesByAddress_;
        size_t tlsModuleCount_ = 0;
        std::string libraryDirectory_;
        LinkMap* requester_ = nullptr;
        // Images whose symbols every later relocation may use, in load order.
        std::vector<LinkMap*> globalImages_;
    };

    struct LoadedElf final: public ElfImage {
        explicit LoadedElf(LinkMap& image);

        void* lookup(std::string_view symbol) const override;

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
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 || header.e_type != ET_DYN || header.e_phentsize != sizeof(Elf64_Phdr)) {
        throwError("%s: not a supported x86-64 ET_DYN ELF", resolved->c_str());
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
    auto* mapping = mmap(nullptr, image.mapSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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
            file.read(reinterpret_cast<void*>(image.base + programHeader.p_vaddr), programHeader.p_filesz, static_cast<off_t>(programHeader.p_offset));
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
    image.parseDynamic();
    if (!image.soname.empty()) {
        imagesByName_.emplace(image.soname, &image);
    }
    loadDependencies(image);

    std::vector<DeferredRelocation> deferred;

    applyRelocations(image, deferred);
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
    image.runInitializers();

    return imagePointer;
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

void* Loader::lookup(LinkMap& image, std::string_view name) {
    std::lock_guard lock(mutex_);

    return materialize(searchScope(image, name, {}));
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
        if (image->tlsModule) {
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

    static constexpr std::array systemDirectories = {
        std::string_view("/usr/lib"),
        std::string_view("/lib"),
        std::string_view("/usr/lib64"),
        std::string_view("/lib64"),
        std::string_view("/usr/lib/x86_64-linux-gnu"),
        std::string_view("/lib/x86_64-linux-gnu"),
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

bool Loader::isGlibcDependency(const std::string_view& name) noexcept {
    static constexpr std::array dependencies = {
        std::string_view("libc.so.6"),
        std::string_view("libpthread.so.0"),
        std::string_view("libdl.so.2"),
        std::string_view("libm.so.6"),
        std::string_view("librt.so.1"),
        std::string_view("ld-linux-x86-64.so.2"),
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

    if (!strings || !symbols || !gnuHash) {
        throwError("%s: missing dynamic string, symbol, or GNU hash table", path.c_str());
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

static uint32_t gnuSymbolHash(const std::string_view& name) noexcept {
    uint32_t hash = 5381;

    for (auto character : name) {
        hash = hash * 33 + static_cast<unsigned char>(character);
    }

    return hash;
}

Definition LinkMap::findSymbol(const std::string_view& name, const std::string_view& version) noexcept {
    if (!gnuHash) {
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
            auto* symbol = &symbols[index];
            auto foundVersion = symbolVersion(index);
            auto hidden = symbolVersions && (symbolVersions[index] & 0x8000);
            auto versionMatches = version.empty() ? !hidden : foundVersion == version;
            auto visibility = ELF64_ST_VISIBILITY(symbol->st_other);

            if (symbol->st_name < stringsSize && std::string_view(strings + symbol->st_name) == name && symbol->st_shndx != SHN_UNDEF && versionMatches && visibility != STV_HIDDEN && visibility != STV_INTERNAL) {
                return {base + symbol->st_value, this, symbol};
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

    if (symbol->st_shndx != SHN_UNDEF) {
        return {image.base + symbol->st_value, &image, symbol};
    }
    if (symbol->st_name >= image.stringsSize) {
        throwError("%s: symbol name outside the string table", image.path.c_str());
    }

    std::string_view name(image.strings + symbol->st_name);
    auto version = image.symbolVersion(symbolIndex);
    auto weak = ELF64_ST_BIND(symbol->st_info) == STB_WEAK;

    if (image.glibcAbi) {
        if (auto* address = resolveGlibcOverride(name, version); address) {
            return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
        }
    }

    if (auto definition = searchScope(image, name, version); definition) {
        return definition;
    }
    for (auto* global : globalImages_) {
        if (auto definition = global->findSymbol(name, version); definition) {
            return definition;
        }
    }

    auto* address = image.glibcAbi ? resolveGlibcSymbol(name, version, weak) : nullptr;

    if (!address && !weak) {
        throwError("%s: unresolved symbol %.*s%.*s%.*s", image.path.c_str(), static_cast<int>(name.size()), name.data(), version.empty() ? 0 : 1, "@", static_cast<int>(version.size()), version.data());
    }

    return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
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
        auto resolver = reinterpret_cast<uintptr_t (*)()>(definition.address);

        return reinterpret_cast<void*>(resolver());
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

    if (type == R_X86_64_RELATIVE) {
        *where = image.base + relocation.r_addend;
        return false;
    }
    if (type == R_X86_64_IRELATIVE) {
        if (!allowIfunc) {
            return true;
        }

        auto resolver = reinterpret_cast<uintptr_t (*)()>(image.base + relocation.r_addend);
        *where = resolver();
        return false;
    }
    if (!symbolIndex) {
        if (type == R_X86_64_DTPMOD64) {
            if (!image.tlsModule) {
                throwError("%s: local TLS relocation has no module", image.path.c_str());
            }
            *where = reinterpret_cast<uintptr_t>(&image);
            return false;
        }
        if (type == R_X86_64_DTPOFF64) {
            *where = relocation.r_addend;
            return false;
        }
        if (type == R_X86_64_TLSDESC) {
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
        auto resolver = reinterpret_cast<uintptr_t (*)()>(definition.address);
        definition.address = resolver();
    }

    switch (type) {
        case R_X86_64_64:
            *where = definition.address + relocation.r_addend;
            return false;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            *where = definition.address;
            return false;
        case R_X86_64_DTPMOD64:
            if (!symbolIndex) {
                definition.image = &image;
            }
            if (!definition.image || !definition.image->tlsModule) {
                throwError("%s: TLS module relocation has no ELF TLS provider", image.path.c_str());
            }
            *where = reinterpret_cast<uintptr_t>(definition.image);
            return false;
        case R_X86_64_DTPOFF64:
            if (!symbolIndex) {
                *where = relocation.r_addend;
                return false;
            }
            if (!definition.image || !definition.symbol || !definition.image->tlsModule) {
                throwError("%s: TLS offset relocation has no ELF TLS provider", image.path.c_str());
            }
            *where = definition.symbol->st_value + relocation.r_addend;
            return false;
        case R_X86_64_TLSDESC: {
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
        default:
            throwError("%s: unsupported x86-64 relocation type %u at %#lx", image.path.c_str(), type, static_cast<unsigned long>(relocation.r_offset));
    }
}

void Loader::applyRelocations(LinkMap& image, std::vector<DeferredRelocation>& deferred) {
    image.applyRelativeRelocations();

    const std::array tables = {
        std::pair(image.relocations, image.relocationCount),
        std::pair(image.pltRelocations, image.pltRelocationCount),
    };

    for (const auto& [relocations, count] : tables) {
        for (size_t index = 0; index < count; ++index) {
            if (applyRelocation(image, relocations[index], false)) {
                deferred.push_back({&image, &relocations[index]});
            }
        }
    }
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
    return Loader::instance().lookup(image_, symbol);
}

ElfImage::~ElfImage() noexcept {
}

ElfImage* ElfImage::loadElf(std::string_view path, int flags) {
    auto* image = Loader::instance().load(path, flags);

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

extern "C" void* elfTlsAddress(const uintptr_t index[2]) {
    return reinterpret_cast<const LinkMap*>(index[0])->tlsAddress(index[1]);
}

extern "C" void* elfTlsDescAddress(const void* opaqueArgument) {
    const auto& argument = *static_cast<const TlsDescArgument*>(opaqueArgument);

    return argument.image->tlsAddress(argument.offset);
}
