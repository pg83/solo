#include "fts.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

using namespace dyn;

// The walk never chdir()s: fts_accpath is always the full path, which is
// valid from any working directory, so FTS_NOCHDIR is effectively always on.
// FTS_NOSTAT is likewise ignored: every entry is stat'ed, so callers see full
// information where glibc would hand them FTS_NSOK.
namespace {
    // The unread children of one directory; the bottom frame holds the roots
    // under the synthetic level -1 parent.
    struct Frame {
        FtsEntry* directory;
        std::vector<FtsEntry*> children;
        size_t next;
    };

    struct Walk: Fts {
        std::string buffer;
        std::vector<Frame> frames;
        FtsEntry* rootParent = nullptr;
        int (*compare)(const FtsEntry**, const FtsEntry**) = nullptr;
        bool started = false;
        bool finished = false;
    };

    // One allocation per entry: the name inline, the stat block behind it.
    static FtsEntry* allocateEntry(FtsEntry* parent, const char* name, short level) {
        auto nameLength = strlen(name);
        auto statOffset = (sizeof(FtsEntry) + nameLength + 7) & ~size_t(7);
        auto* entry = static_cast<FtsEntry*>(calloc(1, statOffset + sizeof(struct stat)));

        if (!entry) {
            abort();
        }
        entry->fts_parent = parent;
        entry->fts_level = level;
        entry->fts_instr = FTS_NOINSTR;
        entry->fts_namelen = static_cast<unsigned short>(nameLength);
        entry->fts_statp = reinterpret_cast<struct stat*>(reinterpret_cast<char*>(entry) + statOffset);
        memcpy(entry->fts_name, name, nameLength + 1);

        return entry;
    }

    // The entry's full path, root name included, rebuilt from the parent
    // chain into the walk's shared buffer, which is what every entry's
    // fts_path points at, exactly like glibc's shared path buffer.
    static void buildPath(Walk& walk, FtsEntry* entry) {
        std::vector<const FtsEntry*> chain;

        for (const auto* step = entry; step->fts_level >= 0; step = step->fts_parent) {
            chain.push_back(step);
        }
        walk.buffer.clear();
        for (auto step = chain.rbegin(); step != chain.rend(); ++step) {
            if (step != chain.rbegin() && !walk.buffer.empty() && walk.buffer.back() != '/') {
                walk.buffer += '/';
            }
            walk.buffer += (*step)->fts_name;
        }
        entry->fts_path = walk.buffer.data();
        entry->fts_accpath = walk.buffer.data();
        entry->fts_pathlen = static_cast<unsigned short>(std::min(walk.buffer.size(), size_t(65535)));
        walk.fts_path = walk.buffer.data();
    }

    static FtsEntry* deliver(Walk& walk, FtsEntry* entry, int info) {
        entry->fts_info = static_cast<unsigned short>(info);
        entry->fts_instr = FTS_NOINSTR;
        walk.fts_cur = entry;

        return entry;
    }

    // Classify the entry: stat it per the walk's options, set fts_info.
    static FtsEntry* enter(Walk& walk, FtsEntry* entry, bool follow) {
        buildPath(walk, entry);

        auto* status = entry->fts_statp;
        auto logical = (walk.fts_options & FTS_LOGICAL) || follow || ((walk.fts_options & FTS_COMFOLLOW) && entry->fts_level == 0);

        if (logical ? stat(walk.buffer.c_str(), status) : lstat(walk.buffer.c_str(), status)) {
            if (logical && lstat(walk.buffer.c_str(), status) == 0 && S_ISLNK(status->st_mode)) {
                return deliver(walk, entry, FTS_SLNONE);
            }
            entry->fts_errno = errno;

            return deliver(walk, entry, FTS_NS);
        }
        entry->fts_ino = status->st_ino;
        entry->fts_dev = status->st_dev;
        entry->fts_nlink = status->st_nlink;
        if (strcmp(entry->fts_name, ".") == 0 || strcmp(entry->fts_name, "..") == 0) {
            if (entry->fts_level > 0) {
                return deliver(walk, entry, FTS_DOT);
            }
        }
        if (S_ISDIR(status->st_mode)) {
            for (auto* ancestor = entry->fts_parent; ancestor->fts_level >= 0; ancestor = ancestor->fts_parent) {
                if (ancestor->fts_ino == status->st_ino && ancestor->fts_dev == status->st_dev) {
                    entry->fts_cycle = ancestor;

                    return deliver(walk, entry, FTS_DC);
                }
            }

            return deliver(walk, entry, FTS_D);
        }
        if (S_ISLNK(status->st_mode)) {
            return deliver(walk, entry, FTS_SL);
        }
        if (S_ISREG(status->st_mode)) {
            return deliver(walk, entry, FTS_F);
        }

        return deliver(walk, entry, FTS_DEFAULT);
    }

    // The next unread child of the top directory, or the directory's
    // post-order visit once its children are done.
    static FtsEntry* advance(Walk& walk) {
        auto& top = walk.frames.back();

        if (top.next < top.children.size()) {
            return enter(walk, top.children[top.next++], false);
        }

        auto done = std::move(walk.frames.back());

        walk.frames.pop_back();
        for (auto* child : done.children) {
            free(child);
        }
        if (done.directory->fts_level < 0) {
            walk.finished = true;
            walk.fts_cur = nullptr;
            errno = 0;

            return nullptr;
        }
        buildPath(walk, done.directory);

        return deliver(walk, done.directory, FTS_DP);
    }

    // Read the children of the directory whose pre-order visit the caller
    // just consumed.
    static FtsEntry* descend(Walk& walk, FtsEntry* directory) {
        if (walk.fts_options & FTS_XDEV) {
            auto* root = directory;

            while (root->fts_level > 0) {
                root = root->fts_parent;
            }
            if (directory->fts_dev != root->fts_dev) {
                buildPath(walk, directory);

                return deliver(walk, directory, FTS_DP);
            }
        }

        buildPath(walk, directory);

        auto* stream = opendir(walk.buffer.c_str());

        if (!stream) {
            directory->fts_errno = errno;

            return deliver(walk, directory, FTS_DNR);
        }

        std::vector<FtsEntry*> children;

        while (auto* item = readdir(stream)) {
            auto dot = strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0;

            if (dot && !(walk.fts_options & FTS_SEEDOT)) {
                continue;
            }
            children.push_back(allocateEntry(directory, item->d_name, static_cast<short>(directory->fts_level + 1)));
        }
        closedir(stream);
        if (walk.compare) {
            std::sort(children.begin(), children.end(), [&walk](const FtsEntry* left, const FtsEntry* right) {
                return walk.compare(&left, &right) < 0;
            });
        }
        for (size_t index = 0; index + 1 < children.size(); ++index) {
            children[index]->fts_link = children[index + 1];
        }
        if (children.empty()) {
            return deliver(walk, directory, FTS_DP);
        }
        walk.frames.push_back({directory, std::move(children), 0});

        return advance(walk);
    }
}

Fts* dyn::ftsOpen(char* const* paths, int options, int (*compare)(const FtsEntry**, const FtsEntry**)) {
    if (options & ~FTS_OPTIONMASK) {
        errno = EINVAL;

        return nullptr;
    }

    auto* walk = new Walk();

    *static_cast<Fts*>(walk) = Fts{};
    walk->fts_options = options;
    walk->compare = compare;
    walk->rootParent = allocateEntry(nullptr, "", -1);

    std::vector<FtsEntry*> roots;

    for (auto path = paths; path && *path; ++path) {
        roots.push_back(allocateEntry(walk->rootParent, *path, 0));
    }
    if (compare) {
        std::sort(roots.begin(), roots.end(), [compare](const FtsEntry* left, const FtsEntry* right) {
            return compare(&left, &right) < 0;
        });
    }
    for (size_t index = 0; index + 1 < roots.size(); ++index) {
        roots[index]->fts_link = roots[index + 1];
    }
    walk->frames.push_back({walk->rootParent, std::move(roots), 0});

    return walk;
}

FtsEntry* dyn::ftsRead(Fts* fts) {
    auto& walk = *static_cast<Walk*>(fts);

    if (walk.finished) {
        errno = 0;

        return nullptr;
    }
    if (!walk.started) {
        walk.started = true;

        return advance(walk);
    }

    auto* current = walk.fts_cur;

    if (current->fts_instr == FTS_AGAIN) {
        return enter(walk, current, false);
    }
    if (current->fts_info == FTS_D) {
        if (current->fts_instr == FTS_SKIP) {
            buildPath(walk, current);

            return deliver(walk, current, FTS_DP);
        }

        return descend(walk, current);
    }
    if ((current->fts_info == FTS_SL || current->fts_info == FTS_SLNONE) && current->fts_instr == FTS_FOLLOW) {
        return enter(walk, current, true);
    }

    return advance(walk);
}

int dyn::ftsSet(Fts* fts, FtsEntry* entry, int instruction) {
    (void)fts;
    if (instruction && (instruction < FTS_AGAIN || instruction > FTS_SKIP)) {
        errno = EINVAL;

        return 1;
    }
    entry->fts_instr = static_cast<unsigned short>(instruction);

    return 0;
}

int dyn::ftsClose(Fts* fts) {
    auto* walk = static_cast<Walk*>(fts);

    for (auto& frame : walk->frames) {
        for (auto* child : frame.children) {
            free(child);
        }
    }
    free(walk->rootParent);
    delete walk;

    return 0;
}
