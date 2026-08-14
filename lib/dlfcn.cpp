#include "dlfcn.h"

#if defined(__linux__)
    #include "elf_loader.h"
#endif

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <exception>
#include <string>
#include <string_view>
#include <unordered_map>

namespace {
    static int OpenFD() {
        if (auto env = getenv("DL_STUB_DEBUG"); env && env[0] == '/') {
            if (int fd = open(env, O_WRONLY | O_CREAT | O_APPEND, 0644); fd >= 0) {
                return fd;
            }
        }

        return 1;
    }

    struct Dbg {
        inline void out(const void* buf, size_t len) noexcept {
            static auto xfd = OpenFD();

            write(xfd, buf, len);
        }

        inline void out(const char* s) noexcept {
            if (!s) {
                s = "(null)";
            }

            out(s, strlen(s));
        }

        inline void out(int i) noexcept {
            out(std::to_string(i));
        }

        inline void out(std::string_view s) noexcept {
            out(s.data(), s.size());
        }

        template <typename T>
        inline auto& operator<<(T s) noexcept {
            out(s);

            return *this;
        }
    };

    static inline bool debugEnabled() {
        static const bool enabled = getenv("DL_STUB_DEBUG");

        return enabled;
    }

#define DBG(X)            \
    if (debugEnabled()) { \
        Dbg d;            \
        d << X << "\n";   \
    }

    struct IfaceHandle {
        virtual void* lookup(const std::string_view& s) const = 0;
    };

    struct Handle: public IfaceHandle, public std::unordered_map<std::string, void*> {
        void* lookup(const std::string_view& s) const override {
            if (auto it = find(std::string(s)); it != end()) {
                DBG("found " << s);

                return it->second;
            }

            DBG("not found " << s);

            return nullptr;
        }
    };

    struct Handles: public IfaceHandle, public std::unordered_map<std::string, Handle> {
        // default handle lookup
        void* lookup(const std::string_view& s) const override {
            for (const auto& it : *this) {
                if (auto res = it.second.lookup(s); res) {
                    DBG("found global " << s);

                    return res;
                }
            }

            DBG("not found global " << s);

            return nullptr;
        }

        inline IfaceHandle* findHandle(const std::string& s) {
            DBG("try open handle " << s);

            if (auto it = find(s); it != end()) {
                DBG("found handle " << s);

                return &it->second;
            }

            DBG("not found handle " << s);

            return nullptr;
        }

        inline void registar(const char* lib, const char* symbol, void* ptr) noexcept {
            DBG("register " << lib << ", " << symbol);

            (*this)[lib][symbol] = ptr;
        }

        static inline Handles* instance() noexcept {
            static Handles* h = new Handles();

            return h;
        }
    };

#if defined(__linux__)
    struct ElfHandle: public IfaceHandle {
        explicit ElfHandle(ElfImage* image_)
            : image(image_)
        {
        }

        void* lookup(const std::string_view& symbol) const override {
            return image ? image->lookup(symbol) : nullptr;
        }

        ElfImage* image;
    };
#endif

    static thread_local char DL_ERROR[1024] = {};
    static thread_local bool HAS_DL_ERROR = false;

    static inline void setLastError(const std::string_view& error) noexcept {
        auto size = error.size();

        if (size >= sizeof(DL_ERROR)) {
            size = sizeof(DL_ERROR) - 1;
        }
        memcpy(DL_ERROR, error.data(), size);
        DL_ERROR[size] = 0;
        HAS_DL_ERROR = true;
    }

    static inline void clearLastError() noexcept {
        HAS_DL_ERROR = false;
    }

    static auto lastError() noexcept {
        if (!HAS_DL_ERROR) {
            return static_cast<char*>(nullptr);
        }

        HAS_DL_ERROR = false;

        return DL_ERROR;
    }

    static std::string baseName(const std::string& s) {
        std::string r;

        for (char ch : s) {
            if (ch == '/') {
                r.clear();
            } else {
                r.push_back(ch);
            }
        }

        return r;
    }

    static inline std::string cutPrefix(const std::string& s, const std::string& prefix) {
        if (s.size() > prefix.size()) {
            if (s.substr(0, prefix.size()) == prefix) {
                return s.substr(prefix.size());
            }
        }

        return s;
    }

    static inline std::string cutExt(const std::string& s) {
        std::string r;

        for (char ch : s) {
            if (ch == '.') {
                break;
            }

            r.push_back(ch);
        }

        return r;
    }

    static std::string calcName(const std::string& s) {
        return cutExt(cutPrefix(baseName(s), "lib"));
    }
}

extern "C" void* stub_dlsym(void* handle, const char* symbol) {
    clearLastError();

    try {
        if (handle) {
            if (auto ret = ((IfaceHandle*)handle)->lookup(symbol); ret) {
                return ret;
            }
        }
    } catch (const std::exception& error) {
        setLastError(error.what());
        return nullptr;
    } catch (...) {
        setLastError("unknown dlsym error");
        return nullptr;
    }

    setLastError("symbol not found");

    return nullptr;
}

extern "C" void* stub_dlopen(const char* filename, int mode) {
    clearLastError();

    try {
        DBG("dlopen " << filename << " " << mode);

        if (!filename) {
            filename = "";
        }

        if (strcmp(filename, "") == 0) {
            return Handles::instance();
        }

        if (auto res = Handles::instance()->findHandle(filename); res) {
            return res;
        }

        if (auto res = Handles::instance()->findHandle(calcName(filename)); res) {
            return res;
        }

#if defined(__linux__)
        return new ElfHandle(ElfImage::loadElf(filename, mode));
#endif
    } catch (const std::exception& error) {
        setLastError(error.what());
        return nullptr;
    } catch (...) {
        setLastError("unknown dlopen error");
        return nullptr;
    }

    setLastError("library not found");

    return nullptr;
}

extern "C" int stub_dlclose(void* handle) {
    clearLastError();

    (void)handle;

    return 0;
}

extern "C" char* stub_dlerror(void) {
    return (char*)lastError();
}

extern "C" void stub_dlregister(const char* lib, const char* symbol, void* ptr) {
    Handles::instance()->registar(lib, symbol, ptr);
}

extern "C" int stub_dladdr(const void* addr, Dl_info* info) {
#if defined(__linux__)
    clearLastError();

    try {
        if (info) {
            info->dli_fname = nullptr;
            info->dli_fbase = nullptr;
            info->dli_sname = nullptr;
            info->dli_saddr = nullptr;
        }
        if (addr && info) {
            if (auto found = ElfImage::findAddress(addr); found) {
                info->dli_fname = found->path.data();
                info->dli_fbase = found->base;

                return 1;
            }
        }
    } catch (const std::exception& error) {
        setLastError(error.what());
    } catch (...) {
        setLastError("unknown dladdr error");
    }
#else
    (void)addr;
    (void)info;
#endif

    return 0;
}

// some helpers
#define DL_CAT(X, Y) DL_CA_(X, Y)
#define DL_CA_(X, Y) DL_C__(X, Y)
#define DL_C__(X, Y) X##Y
#define DL_STR(X) DL_ST_(X)
#define DL_ST_(X) #X

#if defined(__COUNTER__)
    #define DL_UID(N) DL_CAT(N, __COUNTER__)
#endif

#if !defined(DL_UID)
    #define DL_UID(N) DL_CAT(N, __LINE__)
#endif

#define DL_LIB(name)            \
    namespace {                 \
        namespace DL_UID(Reg) { \
            static struct Reg { \
                inline Reg() {  \
                    const char* lib = name;

#define DL_S_2(name, ptr) stub_dlregister(lib, name, (void*)ptr);

#define DL_S_1(name) DL_S_2(DL_STR(name), name)

#define DL_END() \
    }            \
    ;            \
    }            \
    LIB_REG;     \
    }            \
    }

DL_LIB("dl")
DL_S_2("dlopen", stub_dlopen)
DL_S_2("dlsym", stub_dlsym)
DL_S_2("dlclose", stub_dlclose)
DL_S_2("dlerror", stub_dlerror)
DL_S_2("dladdr", stub_dladdr)
DL_END()

DL_LIB("c")
DL_S_2("dlopen", stub_dlopen)
DL_S_2("dlsym", stub_dlsym)
DL_S_2("dlclose", stub_dlclose)
DL_S_2("dlerror", stub_dlerror)
DL_S_2("dladdr", stub_dladdr)
DL_END()
