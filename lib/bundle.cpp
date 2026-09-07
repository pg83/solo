// The payload appended to a stub: a trailer at the very end of the file
// points at an index, and the index names page-aligned members. Because the
// members are page-aligned the loader maps them straight out of the stub's
// own file at an offset — nothing is unpacked, the pages come from the one
// file's page cache, and /proc/self/exe keeps pointing at the program the
// user actually ran, so a guest that re-executes itself still works.

#include "bundle.h"

#include "dlfcn.h"
#include "elf_loader.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <exception>
#include <stdexcept>
#include <vector>

using namespace dyn;

namespace {
    [[noreturn]] static void throwError(const char* format, ...) {
        std::array<char, 1024> buffer;
        va_list arguments;

        va_start(arguments, format);
        vsnprintf(buffer.data(), buffer.size(), format, arguments);
        va_end(arguments);

        throw std::runtime_error(buffer.data());
    }

    // The last bytes of a bundled executable. Keeping it at the end is what
    // lets a bundle be built with cat: the stub is a finished binary and
    // the payload is appended to it, so the stub never has to be relinked
    // for a new guest.
    struct Trailer {
        char magic[8];
        uint32_t version;
        uint32_t count;
        uint64_t indexOffset;
        uint64_t indexSize;
    };

    // One member. Names follow the entries in the same index block, so a
    // member that answers to several sonames is simply several entries
    // pointing at one range.
    struct Entry {
        uint64_t offset;
        uint64_t size;
        uint32_t nameOffset;
        uint32_t flags;
    };

    static constexpr char bundleMagic[8] = {'S', 'O', 'L', 'O', 'B', 'N', 'D', 'L'};
    static constexpr uint32_t bundleVersion = 1;
    // The member is the program to run rather than one of its libraries.
    static constexpr uint32_t entryExecutable = 1;

    struct Member {
        std::string name;
        off_t offset = 0;
        uint64_t size = 0;
        bool executable = false;
    };

    // Read once, at the first question anyone asks. The registry is not
    // synchronized and never changes afterwards, like the provider
    // registry it sits beside: everything here happens before the guest
    // exists, let alone its threads.
    struct Bundle {
        int descriptor = -1;
        std::string path;
        std::vector<Member> members;
        // The file carried the trailer's magic. A payload that then
        // disagrees with itself keeps this set and fills error instead of
        // throwing: a broken bundle has to say so, where a file with no
        // payload at all must quietly stay solo's ordinary command.
        bool present = false;
        std::string error;

        static const Bundle& instance();
    };

    // Not being able to name this executable is not a failure: it means
    // there is no bundle to find. A program run where /proc is not mounted
    // — inside a rootfs the loader is exercising, say — is an ordinary solo
    // process, and every name it asks for must still resolve on the host.
    static std::optional<std::string> readExecutablePath() {
        std::array<char, 4096> buffer;
        auto length = readlink("/proc/self/exe", buffer.data(), buffer.size());

        if (length <= 0 || static_cast<size_t>(length) >= buffer.size()) {
            return std::nullopt;
        }

        return std::string(buffer.data(), static_cast<size_t>(length));
    }

    static void readAt(int descriptor, void* destination, size_t size, off_t offset) {
        auto* cursor = static_cast<unsigned char*>(destination);

        while (size) {
            auto result = pread(descriptor, cursor, size, offset);

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

    // Fills the bundle in, or leaves it empty. Being unable to reach or
    // read this executable's own file leaves it empty too: a program with
    // no payload is not an error, it is solo's ordinary command, and the
    // question is asked on every name the loader resolves. Only a file that
    // does carry the magic and then disagrees with itself is fatal.
    static void readBundleImpl(Bundle& bundle) {
        auto found = readExecutablePath();

        if (!found) {
            return;
        }

        auto path = *found;
        auto descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);

        if (descriptor < 0) {
            return;
        }

        struct stat status;

        if (fstat(descriptor, &status)) {
            close(descriptor);

            return;
        }

        auto fileSize = static_cast<uint64_t>(status.st_size);
        Trailer trailer;

        if (fileSize < sizeof(trailer)) {
            close(descriptor);

            return;
        }

        // Tolerantly: until the magic is in hand this is a guess about an
        // arbitrary file, and a short or unreadable tail only means no.
        if (pread(descriptor, &trailer, sizeof(trailer), static_cast<off_t>(fileSize - sizeof(trailer))) != static_cast<ssize_t>(sizeof(trailer))) {
            close(descriptor);

            return;
        }

        if (memcmp(trailer.magic, bundleMagic, sizeof(bundleMagic)) != 0) {
            close(descriptor);

            return;
        }

        // Past this point the file has declared itself a bundle, so every
        // disagreement below is an error worth reporting rather than a
        // reason to fall back to the command line.
        bundle.present = true;
        bundle.path = path;

        if (trailer.version != bundleVersion) {
            close(descriptor);
            throwError("%s: bundle version %u, this loader speaks %u", path.c_str(), trailer.version, bundleVersion);
        }

        auto entriesSize = static_cast<uint64_t>(trailer.count) * sizeof(Entry);

        // Every entry names itself, so the index is always longer than the
        // entries alone; a bundle with nothing in it is malformed, not empty.
        if (!trailer.count || trailer.indexSize <= entriesSize || trailer.indexOffset > fileSize || trailer.indexSize > fileSize - trailer.indexOffset) {
            close(descriptor);
            throwError("%s: the bundle index does not lie within the file", path.c_str());
        }

        std::vector<unsigned char> index(trailer.indexSize);

        readAt(descriptor, index.data(), index.size(), static_cast<off_t>(trailer.indexOffset));

        // Names live past the entries in the same block, and the block must
        // end with a NUL so that every name in it is terminated.
        auto* names = reinterpret_cast<const char*>(index.data());

        if (index.back() != 0) {
            close(descriptor);
            throwError("%s: the bundle's name table is not terminated", path.c_str());
        }

        auto pageSize = sysconf(_SC_PAGESIZE);

        if (pageSize <= 0) {
            close(descriptor);
            throwError("%s: cannot determine page size", path.c_str());
        }

        for (uint32_t position = 0; position < trailer.count; ++position) {
            Entry entry;

            memcpy(&entry, index.data() + position * sizeof(Entry), sizeof(entry));

            if (entry.nameOffset < entriesSize || entry.nameOffset >= index.size()) {
                close(descriptor);
                throwError("%s: bundle member %u names itself outside the index", path.c_str(), position);
            }
            if (entry.offset > fileSize || entry.size > fileSize - entry.offset) {
                close(descriptor);
                throwError("%s: bundle member %s does not lie within the file", path.c_str(), names + entry.nameOffset);
            }
            // The loader maps a member with the file offsets its program
            // headers carry, biased by this base; only a page-aligned base
            // keeps those offsets congruent to the addresses they load at.
            if (entry.offset % static_cast<uint64_t>(pageSize)) {
                close(descriptor);
                throwError("%s: bundle member %s starts at %llu, which is not page-aligned", path.c_str(), names + entry.nameOffset, static_cast<unsigned long long>(entry.offset));
            }

            bundle.members.push_back({
                names + entry.nameOffset,
                static_cast<off_t>(entry.offset),
                entry.size,
                (entry.flags & entryExecutable) != 0,
            });
        }

        bundle.descriptor = descriptor;
    }

    static void readBundle(Bundle& bundle) {
        try {
            readBundleImpl(bundle);
        } catch (const std::exception& failure) {
            bundle.error = failure.what();
            bundle.members.clear();
            bundle.descriptor = -1;
        }
    }

    const Bundle& Bundle::instance() {
        static const Bundle bundle = [] {
            Bundle result;

            readBundle(result);

            return result;
        }();

        return bundle;
    }
}

std::optional<ImageSource> dyn::bundleMember(std::string_view name) {
    const auto& bundle = Bundle::instance();

    for (const auto& member : bundle.members) {
        if (member.name == name) {
            // The identity a bundled image reports. The file really is the
            // stub, and saying so keeps ldd, dladdr, and a debugger's view
            // of /proc/self/maps honest about where the bytes came from.
            return ImageSource{bundle.path + "/" + member.name, bundle.descriptor, member.offset};
        }
    }

    return std::nullopt;
}

int soloHasBundle(void) {
    return Bundle::instance().present;
}

int soloBundleMain(int argc, char** argv) {
    try {
        const auto& bundle = Bundle::instance();

        if (!bundle.error.empty()) {
            throwError("%s", bundle.error.c_str());
        }

        const Member* program = nullptr;

        for (const auto& member : bundle.members) {
            if (member.executable) {
                program = &member;

                break;
            }
        }

        if (!program) {
            throwError("%s: no bundled program to run", bundle.path.empty() ? "this executable" : bundle.path.c_str());
        }

        // By name, not by path: the name resolves through the bundle ahead
        // of any directory, and so does every DT_NEEDED the closure brings.
        auto executable = dyn::loadExecutable(program->name);

        // ldd's trace mode, ld.so's way: the closure has printed and
        // nothing runs. It is how the set of libraries a bundle still takes
        // from the host is read off.
        if (traceLoadedObjects()) {
            return 0;
        }

        // argv reaches the guest exactly as received, argv[0] included: the
        // stub's file is the program, so the guest's own idea of how it was
        // invoked stays true and re-executing it runs the bundle again.
        dyn::enterExecutable(executable, bundle.path.c_str(), argc, argv);
    } catch (const std::exception& error) {
        fprintf(stderr, "solo: %s\n", error.what());
    } catch (...) {
        fprintf(stderr, "solo: unknown error\n");
    }

    return 127;
}
