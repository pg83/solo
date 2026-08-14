#if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
#endif

#include "elf_loader.h"

#include "dlfcn.h"
#include "glibc_shim.h"

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

#ifndef DT_RELR
    #define DT_RELR 36
    #define DT_RELRSZ 35
    #define DT_RELRENT 37
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
    constexpr size_t MAX_TLS_MODULES = 128;
    constexpr size_t MAX_VERSION_INDEX = 256;

    thread_local std::array<void*, MAX_TLS_MODULES> THREAD_TLS = {};

    [[noreturn]] void throwError(const char* format, ...) {
        std::array<char, 1024> buffer;
        va_list arguments;

        va_start(arguments, format);
        vsnprintf(buffer.data(), buffer.size(), format, arguments);
        va_end(arguments);

        throw std::runtime_error(buffer.data());
    }

    uintptr_t alignDown(uintptr_t value, uintptr_t alignment) {
        return value & ~(alignment - 1);
    }

    uintptr_t alignUp(uintptr_t value, uintptr_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    int segmentProtection(uint32_t flags) {
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
        explicit File(const std::string& path)
            : descriptor_(open(path.c_str(), O_RDONLY | O_CLOEXEC))
        {
            if (descriptor_ < 0) {
                throwError("open(%s): %s", path.c_str(), strerror(errno));
            }
        }

        ~File() {
            if (descriptor_ >= 0) {
                close(descriptor_);
            }
        }

        void read(void* destination, size_t size, off_t offset) const {
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

        int descriptor_;
    };

    struct LinkMap;

    struct Definition {
        uintptr_t address = 0;
        LinkMap* image = nullptr;
        Elf64_Sym* symbol = nullptr;

        explicit operator bool() const noexcept {
            return address != 0;
        }
    };

    struct Dependency {
        std::string name;
        void* handle = nullptr;
        LinkMap* image = nullptr;
    };

    struct TlsDescArgument {
        uintptr_t module;
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
        uintptr_t base = 0;
        uintptr_t mapStart = 0;
        size_t mapSize = 0;
        std::vector<Elf64_Phdr> programHeaders;

        Elf64_Dyn* dynamic = nullptr;
        const char* strings = nullptr;
        size_t stringsSize = 0;
        Elf64_Sym* symbols = nullptr;
        uint32_t* gnuHash = nullptr;
        Elf64_Half* symbolVersions = nullptr;
        std::array<std::string_view, MAX_VERSION_INDEX> versionNames = {};
        std::vector<Dependency> dependencies;

        Elf64_Rela* relocations = nullptr;
        size_t relocationCount = 0;
        Elf64_Rela* pltRelocations = nullptr;
        size_t pltRelocationCount = 0;
        Elf64_Addr* relativeRelocations = nullptr;
        size_t relativeRelocationCount = 0;

        uintptr_t initializer = 0;
        uintptr_t initializerArray = 0;
        size_t initializerCount = 0;
        uintptr_t relroStart = 0;
        size_t relroSize = 0;

        size_t tlsModule = 0;
        uintptr_t tlsTemplate = 0;
        size_t tlsFileSize = 0;
        size_t tlsMemorySize = 0;
        size_t tlsAlignment = 0;

        State state = State::Loading;
    };

    struct DeferredRelocation {
        LinkMap* image;
        const Elf64_Rela* relocation;
    };

    struct StringHash {
        using is_transparent = void;

        size_t operator()(const std::string_view& value) const noexcept {
            return std::hash<std::string_view>()(value);
        }
    };

    extern "C" uintptr_t elfTlsDescEntry();

    struct Loader {
        static Loader& instance() {
            static auto* loader = new Loader();

            return *loader;
        }

        LinkMap* load(const std::string_view& requestedPath, int flags) {
            std::lock_guard lock(mutex_);

            if (requestedPath.empty()) {
                throwError("empty ELF image path");
            }

            if (auto* image = findByName(requestedPath); image) {
                if (image->state == LinkMap::State::Failed) {
                    throwError("%s: a previous load failed", image->path.c_str());
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

            struct MarkFailed {
                ~MarkFailed() {
                    if (image.state == LinkMap::State::Loading) {
                        image.state = LinkMap::State::Failed;
                    }
                }

                LinkMap& image;
            } markFailed{image};

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
                    image.tlsModule = addTlsModule(image);
                    if (!image.tlsModule) {
                        throwError("%s: too many TLS modules", image.path.c_str());
                    }
                    image.tlsTemplate = image.base + programHeader.p_vaddr;
                    image.tlsFileSize = programHeader.p_filesz;
                    image.tlsMemorySize = programHeader.p_memsz;
                    image.tlsAlignment = programHeader.p_align;
                }
            }

            if (!image.dynamic) {
                throwError("%s: missing PT_DYNAMIC", image.path.c_str());
            }
            parseDynamic(image);
            if (!image.soname.empty()) {
                imagesByName_.emplace(image.soname, &image);
            }
            loadDependencies(image);

            std::vector<DeferredRelocation> deferred;

            applyRelocations(image, deferred);
            protect(image);

            for (const auto& item : deferred) {
                applyRelocation(*item.image, *item.relocation, true);
            }
            applyRelro(image);

            image.state = LinkMap::State::Ready;
            runInitializers(image);

            return imagePointer;
        }

        void* lookup(LinkMap& image, const std::string_view& name) {
            std::lock_guard lock(mutex_);
            std::unordered_set<LinkMap*> visited;

            return lookup(image, name, visited);
        }

        void* lookup(LinkMap& image, const std::string_view& name, std::unordered_set<LinkMap*>& visited) {
            if (!visited.insert(&image).second) {
                return nullptr;
            }

            if (auto definition = findSymbol(image, name, {}); definition) {
                return materialize(definition);
            }

            std::string symbol(name);
            for (const auto& dependency : image.dependencies) {
                if (dependency.image) {
                    if (auto* address = lookup(*dependency.image, name, visited); address) {
                        return address;
                    }
                    continue;
                }
                if (auto* address = stub_dlsym(dependency.handle, symbol.c_str()); address) {
                    return address;
                }
                stub_dlerror();
            }

            return nullptr;
        }

        void* tlsAddress(size_t module, size_t offset) {
            std::lock_guard lock(mutex_);

            if (!module || module >= tlsModules_.size() || !tlsModules_[module]) {
                throwError("invalid TLS module %zu", module);
            }

            const auto& image = *tlsModules_[module];

            if (offset >= image.tlsMemorySize) {
                throwError("TLS offset %zu exceeds module %zu size %zu", offset, module, image.tlsMemorySize);
            }

            if (!THREAD_TLS[module]) {
                auto alignment = std::max(image.tlsAlignment, sizeof(void*));
                void* block = nullptr;

                if (posix_memalign(&block, alignment, image.tlsMemorySize)) {
                    throwError("cannot allocate TLS module %zu", module);
                }

                memset(block, 0, image.tlsMemorySize);
                memcpy(block, reinterpret_cast<const void*>(image.tlsTemplate), image.tlsFileSize);
                THREAD_TLS[module] = block;
            }

            return static_cast<unsigned char*>(THREAD_TLS[module]) + offset;
        }

        std::optional<ElfAddress> findAddress(const void* address) {
            std::lock_guard lock(mutex_);
            auto needle = reinterpret_cast<uintptr_t>(address);
            auto image = imagesByAddress_.upper_bound(needle);

            if (image == imagesByAddress_.begin()) {
                return std::nullopt;
            }
            --image;
            if (needle >= image->second->mapStart + image->second->mapSize) {
                return std::nullopt;
            }

            return ElfAddress{
                image->second->path,
                reinterpret_cast<void*>(image->second->base),
            };
        }

        int iterateProgramHeaders(ElfProgramHeaderCallback callback, void* data) {
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
                if (image->tlsModule < THREAD_TLS.size()) {
                    tlsData = THREAD_TLS[image->tlsModule];
                }
                const ElfProgramHeaders headers{
                    image->path.c_str(),
                    image->base,
                    image->programHeaders.data(),
                    static_cast<Elf64_Half>(image->programHeaders.size()),
                    image->tlsModule,
                    tlsData,
                };
                if (const int result = callback(headers, data); result) {
                    return result;
                }
            }

            return 0;
        }

        Loader()
            : tlsModules_(1, nullptr)
        {
        }

        LinkMap* findByName(const std::string_view& name) const noexcept {
            if (auto image = imagesByName_.find(name); image != imagesByName_.end()) {
                return image->second;
            }

            return nullptr;
        }

        LinkMap* findByPath(const std::string& path) const noexcept {
            return findByName(path);
        }

        static std::optional<std::string> realPath(const std::string& path) {
            std::array<char, PATH_MAX> resolved;

            if (!realpath(path.c_str(), resolved.data())) {
                return std::nullopt;
            }

            return std::string(resolved.data());
        }

        static std::optional<std::string> inDirectory(const std::string_view& directory, const std::string_view& name) {
            std::string candidate(directory);

            if (!candidate.empty() && candidate.back() != '/') {
                candidate.push_back('/');
            }
            candidate.append(name);

            return realPath(candidate);
        }

        std::optional<std::string> resolvePath(const std::string_view& path) const {
            if (path.find('/') != std::string_view::npos) {
                return realPath(std::string(path));
            }

            if (const auto* configured = getenv("DL_ELF_LIBRARY_PATH"); configured) {
                std::string_view directories(configured);

                while (!directories.empty()) {
                    auto separator = directories.find(':');
                    auto directory = directories.substr(0, separator);

                    if (!directory.empty()) {
                        if (auto resolved = inDirectory(directory, path); resolved) {
                            return resolved;
                        }
                    }
                    if (separator == std::string_view::npos) {
                        break;
                    }
                    directories.remove_prefix(separator + 1);
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
            };

            for (auto directory : systemDirectories) {
                if (auto resolved = inDirectory(directory, path); resolved) {
                    return resolved;
                }
            }

            return std::nullopt;
        }

        void rememberLibraryDirectory(const std::string& path) {
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

        size_t addTlsModule(LinkMap& image) {
            if (tlsModules_.size() == MAX_TLS_MODULES) {
                return 0;
            }

            tlsModules_.push_back(&image);

            return tlsModules_.size() - 1;
        }

        static bool isGlibcDependency(const std::string_view& name) noexcept {
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

        void loadDependencies(LinkMap& image) {
            for (auto* entry = image.dynamic; entry->d_tag != DT_NULL; ++entry) {
                if (entry->d_tag != DT_NEEDED) {
                    continue;
                }

                std::string needed(image.strings + entry->d_un.d_val);

                if (isGlibcDependency(needed)) {
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

        static void parseVersions(LinkMap& image, uintptr_t needAddress, size_t needCount, uintptr_t definitionAddress, size_t definitionCount) {
            if (needAddress) {
                auto* need = reinterpret_cast<Elf64_Verneed*>(image.base + needAddress);

                for (size_t index = 0; index < needCount; ++index) {
                    auto* auxiliary = reinterpret_cast<Elf64_Vernaux*>(reinterpret_cast<char*>(need) + need->vn_aux);

                    for (size_t item = 0; item < need->vn_cnt; ++item) {
                        auto versionIndex = static_cast<size_t>(auxiliary->vna_other & 0x7fff);

                        if (versionIndex < image.versionNames.size() && auxiliary->vna_name < image.stringsSize) {
                            image.versionNames[versionIndex] = image.strings + auxiliary->vna_name;
                        }
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
                auto* definition = reinterpret_cast<Elf64_Verdef*>(image.base + definitionAddress);

                for (size_t index = 0; index < definitionCount; ++index) {
                    auto* auxiliary = reinterpret_cast<Elf64_Verdaux*>(reinterpret_cast<char*>(definition) + definition->vd_aux);
                    auto versionIndex = static_cast<size_t>(definition->vd_ndx & 0x7fff);

                    if (versionIndex < image.versionNames.size() && auxiliary->vda_name < image.stringsSize) {
                        image.versionNames[versionIndex] = image.strings + auxiliary->vda_name;
                    }
                    if (!definition->vd_next) {
                        break;
                    }
                    definition = reinterpret_cast<Elf64_Verdef*>(reinterpret_cast<char*>(definition) + definition->vd_next);
                }
            }
        }

        static void parseDynamic(LinkMap& image) {
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

            for (auto* entry = image.dynamic; entry->d_tag != DT_NULL; ++entry) {
                switch (entry->d_tag) {
                    case DT_STRTAB:
                        image.strings = reinterpret_cast<const char*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_STRSZ:
                        image.stringsSize = entry->d_un.d_val;
                        break;
                    case DT_SYMTAB:
                        image.symbols = reinterpret_cast<Elf64_Sym*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_GNU_HASH:
                        image.gnuHash = reinterpret_cast<uint32_t*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_VERSYM:
                        image.symbolVersions = reinterpret_cast<Elf64_Half*>(image.base + entry->d_un.d_ptr);
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
                        image.relocations = reinterpret_cast<Elf64_Rela*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_RELASZ:
                        relocationSize = entry->d_un.d_val;
                        break;
                    case DT_RELAENT:
                        relocationEntrySize = entry->d_un.d_val;
                        break;
                    case DT_JMPREL:
                        image.pltRelocations = reinterpret_cast<Elf64_Rela*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_PLTRELSZ:
                        pltRelocationSize = entry->d_un.d_val;
                        break;
                    case DT_RELR:
                        image.relativeRelocations = reinterpret_cast<Elf64_Addr*>(image.base + entry->d_un.d_ptr);
                        break;
                    case DT_RELRSZ:
                        relativeRelocationSize = entry->d_un.d_val;
                        break;
                    case DT_RELRENT:
                        relativeRelocationEntrySize = entry->d_un.d_val;
                        break;
                    case DT_INIT:
                        image.initializer = image.base + entry->d_un.d_ptr;
                        break;
                    case DT_INIT_ARRAY:
                        image.initializerArray = image.base + entry->d_un.d_ptr;
                        break;
                    case DT_INIT_ARRAYSZ:
                        image.initializerCount = entry->d_un.d_val / sizeof(uintptr_t);
                        break;
                    case DT_SONAME:
                        sonameOffset = entry->d_un.d_val;
                        break;
                    default:
                        break;
                }
            }

            if (!image.strings || !image.symbols || !image.gnuHash) {
                throwError("%s: missing dynamic string, symbol, or GNU hash table", image.path.c_str());
            }
            if (relocationSize && relocationEntrySize != sizeof(Elf64_Rela)) {
                throwError("%s: unsupported RELA entry size %zu", image.path.c_str(), relocationEntrySize);
            }
            if (relativeRelocationSize && relativeRelocationEntrySize != sizeof(Elf64_Addr)) {
                throwError("%s: unsupported RELR entry size %zu", image.path.c_str(), relativeRelocationEntrySize);
            }
            if (sonameOffset < image.stringsSize) {
                image.soname = image.strings + sonameOffset;
            }

            image.relocationCount = relocationSize / sizeof(Elf64_Rela);
            image.pltRelocationCount = pltRelocationSize / sizeof(Elf64_Rela);
            image.relativeRelocationCount = relativeRelocationSize / sizeof(Elf64_Addr);
            parseVersions(image, needVersions, needVersionCount, definedVersions, definedVersionCount);
        }

        static std::string_view symbolVersion(const LinkMap& image, size_t symbolIndex) noexcept {
            if (!image.symbolVersions) {
                return {};
            }

            auto versionIndex = static_cast<size_t>(image.symbolVersions[symbolIndex] & 0x7fff);

            if (versionIndex < 2 || versionIndex >= image.versionNames.size()) {
                return {};
            }

            return image.versionNames[versionIndex];
        }

        static uint32_t gnuHash(const std::string_view& name) noexcept {
            uint32_t hash = 5381;

            for (auto character : name) {
                hash = hash * 33 + static_cast<unsigned char>(character);
            }

            return hash;
        }

        static Definition findSymbol(LinkMap& image, const std::string_view& name, const std::string_view& version) noexcept {
            if (!image.gnuHash) {
                return {};
            }

            auto bucketCount = image.gnuHash[0];
            auto symbolOffset = image.gnuHash[1];
            auto bloomSize = image.gnuHash[2];
            auto bloomShift = image.gnuHash[3];

            if (!bucketCount || !bloomSize) {
                return {};
            }

            auto* bloom = reinterpret_cast<Elf64_Xword*>(image.gnuHash + 4);
            auto* buckets = reinterpret_cast<uint32_t*>(bloom + bloomSize);
            auto* chains = buckets + bucketCount;
            auto hash = gnuHash(name);
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
                    auto* symbol = &image.symbols[index];
                    auto foundVersion = symbolVersion(image, index);
                    auto hidden = image.symbolVersions && (image.symbolVersions[index] & 0x8000);
                    auto versionMatches = version.empty() ? !hidden : foundVersion == version;
                    auto visibility = ELF64_ST_VISIBILITY(symbol->st_other);

                    if (std::string_view(image.strings + symbol->st_name) == name && symbol->st_shndx != SHN_UNDEF && versionMatches && visibility != STV_HIDDEN && visibility != STV_INTERNAL) {
                        return {image.base + symbol->st_value, &image, symbol};
                    }
                }
                if (chain & 1) {
                    break;
                }
                ++index;
            }

            return {};
        }

        static Definition findDefinition(LinkMap& image, const std::string_view& name, const std::string_view& version, std::unordered_set<LinkMap*>& visited) {
            if (!visited.insert(&image).second) {
                return {};
            }

            if (auto definition = findSymbol(image, name, version); definition) {
                return definition;
            }
            for (const auto& dependency : image.dependencies) {
                if (!dependency.image) {
                    continue;
                }
                if (auto definition = findDefinition(*dependency.image, name, version, visited); definition) {
                    return definition;
                }
            }

            return {};
        }

        Definition resolveSymbol(LinkMap& image, size_t symbolIndex) {
            auto* symbol = &image.symbols[symbolIndex];

            if (symbol->st_shndx != SHN_UNDEF) {
                return {image.base + symbol->st_value, &image, symbol};
            }

            std::string_view name(image.strings + symbol->st_name);
            auto version = symbolVersion(image, symbolIndex);
            std::string nameString(name);
            std::unordered_set<LinkMap*> visited;

            for (const auto& dependency : image.dependencies) {
                if (dependency.image) {
                    if (auto definition = findDefinition(*dependency.image, name, version, visited); definition) {
                        return definition;
                    }
                    continue;
                }

                if (auto* provider = stub_dlsym(dependency.handle, nameString.c_str()); provider) {
                    return {reinterpret_cast<uintptr_t>(provider), nullptr, nullptr};
                }
                stub_dlerror();
            }

            auto weak = ELF64_ST_BIND(symbol->st_info) == STB_WEAK;
            auto* address = resolveGlibcSymbol(name, version, weak);

            if (!address && !weak) {
                throwError("%s: unresolved symbol %.*s%.*s%.*s", image.path.c_str(), static_cast<int>(name.size()), name.data(), version.empty() ? 0 : 1, "@", static_cast<int>(version.size()), version.data());
            }

            return {reinterpret_cast<uintptr_t>(address), nullptr, nullptr};
        }

        static void* materialize(Definition definition) {
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
                    definition.image->tlsModule,
                    definition.symbol->st_value,
                };

                return elfTlsAddress(index);
            }

            return reinterpret_cast<void*>(definition.address);
        }

        void applyRelativeRelocations(LinkMap& image) {
            uintptr_t* where = nullptr;

            for (size_t index = 0; index < image.relativeRelocationCount; ++index) {
                auto entry = image.relativeRelocations[index];

                if (!(entry & 1)) {
                    where = reinterpret_cast<uintptr_t*>(image.base + entry);
                    *where += image.base;
                    ++where;
                    continue;
                }
                if (!where) {
                    throwError("%s: RELR bitmap appears before an address", image.path.c_str());
                }

                for (unsigned bit = 1; bit < 8 * sizeof(entry); ++bit) {
                    if (entry & (uintptr_t(1) << bit)) {
                        where[bit - 1] += image.base;
                    }
                }
                where += 8 * sizeof(entry) - 1;
            }
        }

        bool applyRelocation(LinkMap& image, const Elf64_Rela& relocation, bool allowIfunc) {
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
                    *where = image.tlsModule;
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
                        image.tlsModule,
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
                    *where = definition.image->tlsModule;
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
                        definition.image->tlsModule,
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

        void applyRelocations(LinkMap& image, std::vector<DeferredRelocation>& deferred) {
            applyRelativeRelocations(image);

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

        static void protect(LinkMap& image) {
            auto pageSize = sysconf(_SC_PAGESIZE);

            if (pageSize <= 0 || mprotect(reinterpret_cast<void*>(image.mapStart), image.mapSize, PROT_NONE)) {
                throwError("%s: mprotect(PROT_NONE): %s", image.path.c_str(), strerror(errno));
            }

            for (const auto& programHeader : image.programHeaders) {
                if (programHeader.p_type != PT_LOAD) {
                    continue;
                }

                auto start = alignDown(image.base + programHeader.p_vaddr, pageSize);
                auto end = alignUp(image.base + programHeader.p_vaddr + programHeader.p_memsz, pageSize);

                if (mprotect(reinterpret_cast<void*>(start), end - start, segmentProtection(programHeader.p_flags))) {
                    throwError("%s: mprotect(PT_LOAD): %s", image.path.c_str(), strerror(errno));
                }
            }
        }

        static void applyRelro(LinkMap& image) {
            if (!image.relroSize) {
                return;
            }

            auto pageSize = sysconf(_SC_PAGESIZE);
            auto start = alignDown(image.base + image.relroStart, pageSize);
            auto end = alignUp(image.base + image.relroStart + image.relroSize, pageSize);

            if (mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ)) {
                throwError("%s: mprotect(RELRO): %s", image.path.c_str(), strerror(errno));
            }
        }

        static void runInitializers(LinkMap& image) {
            if (image.initializer) {
                reinterpret_cast<void (*)()>(image.initializer)();
            }

            auto* initializers = reinterpret_cast<uintptr_t*>(image.initializerArray);

            for (size_t index = 0; index < image.initializerCount; ++index) {
                if (initializers[index] && initializers[index] != UINTPTR_MAX) {
                    reinterpret_cast<void (*)()>(initializers[index])();
                }
            }
        }

        std::recursive_mutex mutex_;
        std::vector<std::unique_ptr<LinkMap>> images_;
        std::unordered_map<std::string, LinkMap*, StringHash, std::equal_to<>> imagesByName_;
        std::map<uintptr_t, LinkMap*> imagesByAddress_;
        std::vector<LinkMap*> tlsModules_;
        std::string libraryDirectory_;
    };

    struct LoadedElf final: public ElfImage {
        explicit LoadedElf(LinkMap& image)
            : image_(image)
        {
        }

        void* lookup(const std::string_view& symbol) const override {
            return Loader::instance().lookup(image_, symbol);
        }

        LinkMap& image_;
    };
}

ElfImage::~ElfImage() noexcept {
}

ElfImage* ElfImage::loadElf(const std::string_view& path, int flags) {
    auto* image = Loader::instance().load(path, flags);

    return image ? new LoadedElf(*image) : nullptr;
}

std::optional<ElfAddress> ElfImage::findAddress(const void* address) {
    return Loader::instance().findAddress(address);
}

int ElfImage::iterateProgramHeaders(ElfProgramHeaderCallback callback, void* data) {
    return Loader::instance().iterateProgramHeaders(callback, data);
}

extern "C" void* elfTlsAddress(const uintptr_t index[2]) {
    return Loader::instance().tlsAddress(index[0], index[1]);
}

extern "C" void* elfTlsDescAddress(const void* opaqueArgument) {
    const auto& argument = *static_cast<const TlsDescArgument*>(opaqueArgument);

    return Loader::instance().tlsAddress(argument.module, argument.offset);
}
