#include "dlfcn.h"

#include "elf_loader.h"
#include "iface_handle.h"
#include "musl_provider.h"
#include "thread_tls.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <exception>
#include <string>
#include <string_view>
#include <unordered_map>

using namespace dyn;

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
        void out(const void* buf, size_t len) noexcept;
        void out(const char* s) noexcept;
        void out(int i) noexcept;
        void out(std::string_view s) noexcept;

        template <typename T>
        auto& operator<<(T s) noexcept;
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

    struct Handle: public IfaceHandle, public std::unordered_map<std::string, void*> {
        void* lookup(std::string_view s) const override;
    };

    struct Handles: public IfaceHandle, public std::unordered_map<std::string, Handle> {
        Handles();

        // default handle lookup
        void* lookup(std::string_view s) const override;
        IfaceHandle* findHandle(const std::string& s);
        void registar(const char* lib, const char* symbol, void* ptr);
        static Handles* instance();
    };

    static inline void setLastError(const std::string_view& error) {
        ThreadTls::current()->setDlError(error);
    }

    static inline void clearLastError() {
        ThreadTls::current()->clearDlError();
    }

    static char* lastError() {
        return ThreadTls::current()->takeDlError();
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

void Dbg::out(const void* buf, size_t len) noexcept {
    static auto xfd = OpenFD();

    write(xfd, buf, len);
}

void Dbg::out(const char* s) noexcept {
    if (!s) {
        s = "(null)";
    }

    out(s, strlen(s));
}

void Dbg::out(int i) noexcept {
    out(std::to_string(i));
}

void Dbg::out(std::string_view s) noexcept {
    out(s.data(), s.size());
}

template <typename T>
auto& Dbg::operator<<(T s) noexcept {
    out(s);

    return *this;
}

void* Handle::lookup(std::string_view s) const {
    if (auto it = find(std::string(s)); it != end()) {
        DBG("found " << s);

        return it->second;
    }

    DBG("not found " << s);

    return nullptr;
}

Handles::Handles() {
    registar("dl", "dlopen", reinterpret_cast<void*>(stub_dlopen));
    registar("dl", "dlsym", reinterpret_cast<void*>(stub_dlsym));
    registar("dl", "dlclose", reinterpret_cast<void*>(stub_dlclose));
    registar("dl", "dlerror", reinterpret_cast<void*>(stub_dlerror));
    registar("dl", "dladdr", reinterpret_cast<void*>(stub_dladdr));

    auto provider = muslProvider();

    for (size_t index = 0; index < provider.symbolCount; ++index) {
        const auto& symbol = provider.symbols[index];

        registar("c", symbol.name, symbol.address);
    }
    for (size_t index = 0; index < provider.overrideCount; ++index) {
        const auto& symbol = provider.overrides[index];

        registar("c", symbol.name, symbol.address);
    }
    registar("c", "dlclose", reinterpret_cast<void*>(stub_dlclose));
    registar("c", "dlerror", reinterpret_cast<void*>(stub_dlerror));
    registar("c", "dladdr", reinterpret_cast<void*>(stub_dladdr));
}

void* Handles::lookup(std::string_view s) const {
    for (const auto& it : *this) {
        if (auto res = it.second.lookup(s); res) {
            DBG("found global " << s);

            return res;
        }
    }

    if (auto* res = ElfImage::lookupGlobal(s); res) {
        DBG("found RTLD_GLOBAL " << s);

        return res;
    }

    DBG("not found global " << s);

    return nullptr;
}

IfaceHandle* Handles::findHandle(const std::string& s) {
    DBG("try open handle " << s);

    if (auto it = find(s); it != end()) {
        DBG("found handle " << s);

        return &it->second;
    }

    DBG("not found handle " << s);

    return nullptr;
}

void Handles::registar(const char* lib, const char* symbol, void* ptr) {
    DBG("register " << lib << ", " << symbol);

    (*this)[lib][symbol] = ptr;
}

Handles* Handles::instance() {
    static Handles* h = new Handles();

    return h;
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

        // The loader keeps one wrapper per image, so repeated dlopen of the
        // same library returns the same handle.
        return ElfImage::loadElf(filename, mode);
    } catch (const std::exception& error) {
        setLastError(error.what());
        return nullptr;
    } catch (...) {
        setLastError("unknown dlopen error");
        return nullptr;
    }
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
    clearLastError();

    try {
        if (info) {
            info->dli_fname = nullptr;
            info->dli_fbase = nullptr;
            info->dli_sname = nullptr;
            info->dli_saddr = nullptr;
        }
        if (addr && info) {
            ElfAddress found;
            if (ElfImage::findAddress(addr, &found)) {
                info->dli_fname = found.path.data();
                info->dli_fbase = found.base;
                if (!found.symbol.empty()) {
                    info->dli_sname = found.symbol.data();
                    info->dli_saddr = found.symbolAddress;
                }

                return 1;
            }
        }
    } catch (const std::exception& error) {
        setLastError(error.what());
    } catch (...) {
        setLastError("unknown dladdr error");
    }

    return 0;
}
