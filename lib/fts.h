#pragma once

#include <sys/stat.h>
#include <sys/types.h>

namespace dyn {
    // The glibc fts(3) ABI: host DSOs (libselinux, libmount) walk file trees
    // through these structures, so the layout matches glibc's fts.h field for
    // field. On x86-64 the fts64 variants use the same layout. The functions
    // live in this namespace, not under the ABI names, so a host application
    // linking its own fts implementation never collides with ours.
    struct FtsEntry {
        FtsEntry* fts_cycle;
        FtsEntry* fts_parent;
        FtsEntry* fts_link;
        long fts_number;
        void* fts_pointer;
        char* fts_accpath;
        char* fts_path;
        int fts_errno;
        int fts_symfd;
        unsigned short fts_pathlen;
        unsigned short fts_namelen;
        ino_t fts_ino;
        dev_t fts_dev;
        nlink_t fts_nlink;
        short fts_level;
        unsigned short fts_info;
        unsigned short fts_flags;
        unsigned short fts_instr;
        struct stat* fts_statp;
        char fts_name[1];
    };

    struct Fts {
        FtsEntry* fts_cur;
        FtsEntry* fts_child;
        FtsEntry** fts_array;
        dev_t fts_dev;
        char* fts_path;
        int fts_rfd;
        int fts_pathlen;
        int fts_nitems;
        int (*fts_compar)(const void*, const void*);
        int fts_options;
    };

    // fts_open options.
    enum {
        FTS_COMFOLLOW = 0x0001,
        FTS_LOGICAL = 0x0002,
        FTS_NOCHDIR = 0x0004,
        FTS_NOSTAT = 0x0008,
        FTS_PHYSICAL = 0x0010,
        FTS_SEEDOT = 0x0020,
        FTS_XDEV = 0x0040,
        FTS_OPTIONMASK = 0x00ff,
    };

    // fts_info values.
    enum {
        FTS_D = 1,
        FTS_DC = 2,
        FTS_DEFAULT = 3,
        FTS_DNR = 4,
        FTS_DOT = 5,
        FTS_DP = 6,
        FTS_ERR = 7,
        FTS_F = 8,
        FTS_INIT = 9,
        FTS_NS = 10,
        FTS_NSOK = 11,
        FTS_SL = 12,
        FTS_SLNONE = 13,
    };

    // fts_set instructions.
    enum {
        FTS_AGAIN = 1,
        FTS_FOLLOW = 2,
        FTS_NOINSTR = 3,
        FTS_SKIP = 4,
    };

    Fts* ftsOpen(char* const* paths, int options, int (*compare)(const FtsEntry**, const FtsEntry**));
    FtsEntry* ftsRead(Fts* fts);
    int ftsSet(Fts* fts, FtsEntry* entry, int instruction);
    int ftsClose(Fts* fts);
}
