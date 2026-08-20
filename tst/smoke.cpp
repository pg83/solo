#include "dlfcn.h"
#include "elf_loader.h"
#include "musl_symbols.h"
#include "fault_report.h"

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <exception>

using namespace dyn;

namespace {
    using EnumerateInstanceVersion = int32_t (*)(uint32_t* version);
    using DynamicDlsym = void* (*)(void* handle, const char* symbol);
    using GlibcLookup = void* (*)(const char* library, const char* symbol);
    using GlibcDefaultLookup = void* (*)(const char* symbol);
    using GlibcVersionLookup = void* (*)(const char* library, const char* symbol, const char* version);
    using GlibcDlFunction = void* (*)(const char* symbol);
    using GlibcTest = int (*)();
    using GlibcThrow = void (*)();
    using GlibcCall = void (*)(void (*callback)());
    using GlibcCatch = int (*)(void (*callback)());
    using LazyValue = int (*)(int);
    using LazyMix = double (*)(int, double, long, double);
    using IeAddress = int* (*)();
    using IeAdd = void (*)(int);
    using BigFirst = unsigned char (*)();

    static GlibcThrow foreignThrow;
    static bool callbackCaught;

    static int testProviderValue(int value) {
        return value + 35;
    }

    static void throwFromStaticWorld() {
        throw 43;
    }

    static void catchForeignInCallback() {
        try {
            foreignThrow();
        } catch (...) {
            callbackCaught = true;
        }
    }

    static void throwForeignFromCallback() {
        foreignThrow();
    }

    // A thread parked before the initial-exec module loads: the documented
    // restriction gives it zeroed TLS for that module, never garbage.
    struct ParkedThread {
        sem_t start;
        sem_t done;
        GlibcTest value;
        int result;
    };

    static void* parkedThreadMain(void* opaque) {
        auto* parked = static_cast<ParkedThread*>(opaque);

        sem_wait(&parked->start);
        parked->result = parked->value();
        sem_post(&parked->done);
        return nullptr;
    }

    struct IeThread {
        GlibcTest selfcheck;
        IeAddress tdataAddress;
        int* mainTdataAddress;
        int result;
    };

    static void* ieThreadMain(void* opaque) {
        auto* state = static_cast<IeThread*>(opaque);

        state->result = state->selfcheck();
        if (state->result == 0 && state->tdataAddress() == state->mainTdataAddress) {
            // The same offset must land in this thread's own block.
            state->result = 100;
        }
        return nullptr;
    }

    static void* requiredSymbol(void* handle, const char* name) {
        auto* address = stub_dlsym(handle, name);

        if (!address) {
            fprintf(stderr, "glibc test symbol missing: %s: %s\n", name, stub_dlerror());
        }

        return address;
    }
}

int main() {
    installFaultReport();

#if defined(__x86_64__)
    auto* libc = stub_dlopen("libc.musl-x86_64.so.1", RTLD_NOW | RTLD_LOCAL);
#elif defined(__aarch64__)
    auto* libc = stub_dlopen("libc.musl-aarch64.so.1", RTLD_NOW | RTLD_LOCAL);
#endif

    if (!libc) {
        fprintf(stderr, "static libc provider failed: %s\n", stub_dlerror());
        return 1;
    }
    auto symbols = muslSymbols();

    for (size_t index = 0; index < symbols.count; ++index) {
        if (!stub_dlsym(libc, symbols.symbols[index].name)) {
            fprintf(stderr, "static libc symbol missing: %s: %s\n", symbols.symbols[index].name, stub_dlerror());
            return 1;
        }
    }
    static constexpr const char* dynamicSymbols[] = {
        "__tls_get_addr",
        "dlopen",
        "dlsym",
        "dlclose",
        "dlerror",
        "dladdr",
    };
    for (const auto* symbol : dynamicSymbols) {
        if (!stub_dlsym(libc, symbol)) {
            fprintf(stderr, "static libc dynamic symbol missing: %s: %s\n", symbol, stub_dlerror());
            return 1;
        }
    }
    static constexpr const char* processSymbols[] = {
        "__libc_start_main",
        "_fini",
        "_init",
    };
    for (const auto* symbol : processSymbols) {
        if (stub_dlsym(libc, symbol)) {
            fprintf(stderr, "static libc process symbol leaked: %s\n", symbol);
            return 1;
        }
    }

    auto dynamicDlsym = reinterpret_cast<DynamicDlsym>(stub_dlsym(libc, "dlsym"));
    auto* rawStrchr = stub_dlsym(libc, "strchr");

    if (!dynamicDlsym || dynamicDlsym(nullptr, "strchr") != rawStrchr) {
        fprintf(stderr, "musl RTLD_DEFAULT lookup failed\n");
        return 1;
    }

    stub_dlregister("test-provider", "test_provider_value", reinterpret_cast<void*>(testProviderValue));

    auto* glibc = stub_dlopen("libdlfcn-test-glibc.so", RTLD_NOW | RTLD_LOCAL);

    if (!glibc) {
        fprintf(stderr, "glibc test load failed: %s\n", stub_dlerror());
        return 1;
    }

    // File-backed segment mappings keep the library's path in the maps,
    // which is what profilers and debuggers key on.
    auto* maps = fopen("/proc/self/maps", "r");
    auto mapsNamed = false;
    char mapsLine[512];
    while (maps && fgets(mapsLine, sizeof(mapsLine), maps)) {
        if (strstr(mapsLine, "libdlfcn-test-glibc.so")) {
            mapsNamed = true;
        }
    }
    if (maps) {
        fclose(maps);
    }
    if (!mapsNamed) {
        fprintf(stderr, "loaded image has no name in /proc/self/maps\n");
        return 1;
    }

    auto glibcLookup = reinterpret_cast<GlibcLookup>(requiredSymbol(glibc, "glibc_test_lookup"));
    auto glibcDefaultLookup = reinterpret_cast<GlibcDefaultLookup>(requiredSymbol(glibc, "glibc_test_default_lookup"));
    auto glibcVersionLookup = reinterpret_cast<GlibcVersionLookup>(requiredSymbol(glibc, "glibc_test_version_lookup"));
    auto glibcDlFunction = reinterpret_cast<GlibcDlFunction>(requiredSymbol(glibc, "glibc_test_dl_function"));
    auto glibcFactory = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_factory"));
    auto glibcOwnSymbol = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_own_symbol"));
    auto glibcThread = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_thread"));
    auto glibcThreadTls = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_thread_tls"));
    auto glibcManyPthreadObjects = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_many_pthread_objects"));
    auto glibcError = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_error"));
    auto glibcClose = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_close"));
    auto glibcGlobal = reinterpret_cast<GlibcTest>(requiredSymbol(glibc, "glibc_test_global"));
    auto glibcNext = reinterpret_cast<GlibcDlFunction>(requiredSymbol(glibc, "glibc_test_next"));

    if (!glibcLookup || !glibcDefaultLookup || !glibcVersionLookup || !glibcDlFunction || !glibcFactory || !glibcOwnSymbol || !glibcThread || !glibcThreadTls || !glibcManyPthreadObjects || !glibcError || !glibcClose || !glibcGlobal || !glibcNext) {
        return 1;
    }

    static constexpr const char* passthroughSymbols[] = {
        "free",
        "malloc",
        "memcpy",
        "strchr",
        "strlen",
    };
    for (const auto* symbol : passthroughSymbols) {
        auto* expected = stub_dlsym(libc, symbol);
        auto* found = glibcLookup("libc.so.6", symbol);

        if (!expected || found != expected) {
            fprintf(stderr, "glibc libc passthrough failed: %s expected=%p found=%p\n", symbol, expected, found);
            return 1;
        }
    }

    auto* rawCos = stub_dlsym(libc, "cos");

    if (glibcDefaultLookup("strchr") != rawStrchr || glibcDlFunction("strchr") != rawStrchr || glibcLookup("libm.so.6", "cos") != rawCos) {
        fprintf(stderr, "glibc runtime alias passthrough failed\n");
        return 1;
    }
    if (glibcFactory() != 42) {
        fprintf(stderr, "glibc static factory lookup failed\n");
        return 1;
    }
    if (glibcOwnSymbol() != 97) {
        fprintf(stderr, "glibc ELF handle lookup failed\n");
        return 1;
    }

    auto* rawPthreadCreate = stub_dlsym(libc, "pthread_create");
    auto* bridgedPthreadCreate = glibcLookup("libpthread.so.0", "pthread_create");
    // The oldest version glibc ever gave pthread_create on the architecture.
#if defined(__x86_64__)
    auto* oldPthreadCreate = glibcVersionLookup("libc.so.6", "pthread_create", "GLIBC_2.2.5");
#elif defined(__aarch64__)
    auto* oldPthreadCreate = glibcVersionLookup("libc.so.6", "pthread_create", "GLIBC_2.17");
#endif
    auto* newPthreadCreate = glibcVersionLookup("libc.so.6", "pthread_create", "GLIBC_2.34");

    if (!bridgedPthreadCreate || bridgedPthreadCreate == rawPthreadCreate || oldPthreadCreate != bridgedPthreadCreate || newPthreadCreate != bridgedPthreadCreate || glibcDefaultLookup("pthread_create") != bridgedPthreadCreate) {
        fprintf(stderr, "glibc pthread ABI override failed: raw=%p bridge=%p old=%p new=%p\n", rawPthreadCreate, bridgedPthreadCreate, oldPthreadCreate, newPthreadCreate);
        return 1;
    }
    if (!glibcDlFunction("dlsym") || glibcDlFunction("dlsym") == stub_dlsym(libc, "dlsym")) {
        fprintf(stderr, "glibc libdl ABI override failed\n");
        return 1;
    }
    if (auto result = glibcThread(); result != 0) {
        fprintf(stderr, "glibc pthread bridge execution failed: %d\n", result);
        return 1;
    }
    if (auto result = glibcThreadTls(); result != 0) {
        fprintf(stderr, "glibc thread TLS destructor failed: %d\n", result);
        return 1;
    }
    if (auto result = glibcManyPthreadObjects(); result != 0) {
        fprintf(stderr, "glibc pthread object maps failed: %d\n", result);
        return 1;
    }
    if (auto result = glibcError(); result != 0) {
        fprintf(stderr, "glibc dlerror semantics failed: %d\n", result);
        return 1;
    }
    if (glibcClose() != 0) {
        fprintf(stderr, "glibc dlclose contract failed\n");
        return 1;
    }
    if (auto result = glibcGlobal(); result != 0) {
        fprintf(stderr, "glibc RTLD_GLOBAL lookup failed: %d\n", result);
        return 1;
    }
    // crc32 lives in libz, loaded after the test library; the test library's
    // own marker must stay invisible to its RTLD_NEXT.
    if (!glibcNext("crc32") || glibcNext("glibc_test_marker")) {
        fprintf(stderr, "glibc RTLD_NEXT lookup failed\n");
        return 1;
    }

    // Eager binding must reject the unresolvable PLT entry and name it.
    if (stub_dlopen("libdlfcn-test-lazynow.so", RTLD_NOW | RTLD_LOCAL)) {
        fprintf(stderr, "eager load of an unresolvable PLT entry succeeded\n");
        return 1;
    }
    auto* eagerError = stub_dlerror();
    if (!eagerError || !strstr(eagerError, "dlfcn_lazy_undefined_function")) {
        fprintf(stderr, "eager failure did not name the symbol: %s\n", eagerError ? eagerError : "(null)");
        return 1;
    }

    // Lazily the same image loads, and calls resolve on first use with the
    // argument registers intact.
    auto* lazy = stub_dlopen("libdlfcn-test-lazy.so", RTLD_LAZY | RTLD_LOCAL);
    if (!lazy) {
        fprintf(stderr, "lazy load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto lazyValue = reinterpret_cast<LazyValue>(requiredSymbol(lazy, "glibc_lazy_value"));
    auto lazyMix = reinterpret_cast<LazyMix>(requiredSymbol(lazy, "glibc_lazy_mix"));
    auto lazyPid = reinterpret_cast<GlibcTest>(requiredSymbol(lazy, "glibc_lazy_pid"));
    if (!lazyValue || !lazyMix || !lazyPid || !requiredSymbol(lazy, "glibc_lazy_missing_caller")) {
        return 1;
    }
    if (lazyValue(12) != 42) {
        fprintf(stderr, "lazy PLT call through the resolver failed\n");
        return 1;
    }
    if (lazyMix(2, 0.5, 8, 1.5) != 36.5) {
        fprintf(stderr, "lazy resolver clobbered argument registers\n");
        return 1;
    }
    if (lazyPid() <= 0) {
        fprintf(stderr, "lazy cross-library call failed\n");
        return 1;
    }

    // A dlopen issued by loaded code searches the caller's DT_RUNPATH: the
    // host carries -rpath '$ORIGIN/runpath' and loads a sibling that sits
    // outside every other search path.
    auto* runpathHost = stub_dlopen("libdlfcn-test-runpath-host.so", RTLD_NOW | RTLD_LOCAL);
    if (!runpathHost) {
        fprintf(stderr, "runpath host load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto runpathHostValue = reinterpret_cast<GlibcTest>(requiredSymbol(runpathHost, "glibc_runpath_host_value"));
    if (!runpathHostValue || runpathHostValue() != 77) {
        fprintf(stderr, "caller DT_RUNPATH lookup failed\n");
        return 1;
    }

    // The old-dtags counterpart: a caller carrying DT_RPATH only.
    auto* rpathHost = stub_dlopen("libdlfcn-test-rpath-host.so", RTLD_NOW | RTLD_LOCAL);
    if (!rpathHost) {
        fprintf(stderr, "rpath host load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto rpathHostValue = reinterpret_cast<GlibcTest>(requiredSymbol(rpathHost, "glibc_runpath_host_value"));
    if (!rpathHostValue || rpathHostValue() != 77) {
        fprintf(stderr, "caller DT_RPATH lookup failed\n");
        return 1;
    }

    // Initial-exec TLS: one process-wide GOT offset must be valid in every
    // thread through the surplus static arena. The parked thread exists
    // before the module loads and must see zeroed TLS for it.
    ParkedThread parked = {};
    pthread_t parkedThread;
    if (sem_init(&parked.start, 0, 0) || sem_init(&parked.done, 0, 0) || pthread_create(&parkedThread, nullptr, parkedThreadMain, &parked)) {
        fprintf(stderr, "parked thread setup failed\n");
        return 1;
    }

    auto* ie = stub_dlopen("libdlfcn-test-ie.so", RTLD_NOW | RTLD_LOCAL);
    if (!ie) {
        fprintf(stderr, "initial-exec load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto ieSelfcheck = reinterpret_cast<GlibcTest>(requiredSymbol(ie, "glibc_ie_selfcheck"));
    auto ieTdataAddress = reinterpret_cast<IeAddress>(requiredSymbol(ie, "glibc_ie_tdata_address"));
    auto ieTdataValue = reinterpret_cast<GlibcTest>(requiredSymbol(ie, "glibc_ie_tdata_value"));
    auto ieAlignedAddress = reinterpret_cast<IeAddress>(requiredSymbol(ie, "glibc_ie_aligned_address"));
    auto gdTdataAddress = reinterpret_cast<IeAddress>(requiredSymbol(ie, "glibc_gd_tdata_address"));
    auto gdTdataValue = reinterpret_cast<GlibcTest>(requiredSymbol(ie, "glibc_gd_tdata_value"));
    if (!ieSelfcheck || !ieTdataAddress || !ieTdataValue || !ieAlignedAddress || !gdTdataAddress || !gdTdataValue) {
        return 1;
    }
    if (auto result = ieSelfcheck(); result != 0) {
        fprintf(stderr, "initial-exec selfcheck failed: %d\n", result);
        return 1;
    }
    // The selfcheck left 1000 behind; the general-dynamic view of the same
    // variable must be the same memory.
    if (gdTdataAddress() != ieTdataAddress() || gdTdataValue() != 1000) {
        fprintf(stderr, "initial-exec and general-dynamic views diverge\n");
        return 1;
    }
    if (reinterpret_cast<uintptr_t>(ieAlignedAddress()) % 64 != 0) {
        fprintf(stderr, "initial-exec alignment lost\n");
        return 1;
    }

    auto* ieRef = stub_dlopen("libdlfcn-test-ieref.so", RTLD_NOW | RTLD_LOCAL);
    if (!ieRef) {
        fprintf(stderr, "cross-module initial-exec load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto ieRefAddress = reinterpret_cast<IeAddress>(requiredSymbol(ieRef, "glibc_ieref_tdata_address"));
    auto ieRefValue = reinterpret_cast<GlibcTest>(requiredSymbol(ieRef, "glibc_ieref_tdata_value"));
    auto ieRefAdd = reinterpret_cast<IeAdd>(requiredSymbol(ieRef, "glibc_ieref_tdata_add"));
    if (!ieRefAddress || !ieRefValue || !ieRefAdd) {
        return 1;
    }
    if (ieRefAddress() != ieTdataAddress() || ieRefValue() != 1000) {
        fprintf(stderr, "cross-module initial-exec views diverge\n");
        return 1;
    }
    ieRefAdd(1);
    if (ieTdataValue() != 1001) {
        fprintf(stderr, "cross-module initial-exec write lost\n");
        return 1;
    }

    // A thread created after the load starts from the module's template.
    IeThread ieThread = {ieSelfcheck, ieTdataAddress, ieTdataAddress(), -1};
    pthread_t freshThread;
    if (pthread_create(&freshThread, nullptr, ieThreadMain, &ieThread) || pthread_join(freshThread, nullptr)) {
        fprintf(stderr, "initial-exec thread setup failed\n");
        return 1;
    }
    if (ieThread.result != 0) {
        fprintf(stderr, "initial-exec fresh thread failed: %d\n", ieThread.result);
        return 1;
    }
    if (ieTdataValue() != 1001) {
        fprintf(stderr, "fresh thread scribbled over the main thread's TLS\n");
        return 1;
    }

    parked.value = ieTdataValue;
    sem_post(&parked.start);
    sem_wait(&parked.done);
    if (pthread_join(parkedThread, nullptr) || parked.result != 0) {
        fprintf(stderr, "pre-existing thread saw %d instead of zeroed TLS\n", parked.result);
        return 1;
    }

    // Oversized TLS: the general-dynamic module falls back to the dynamic
    // per-thread blocks and keeps its template...
    auto* big = stub_dlopen("libdlfcn-test-bigtls.so", RTLD_NOW | RTLD_LOCAL);
    if (!big) {
        fprintf(stderr, "oversized TLS load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto bigFirst = reinterpret_cast<BigFirst>(requiredSymbol(big, "glibc_big_tls_first"));
    if (!bigFirst || bigFirst() != 11) {
        fprintf(stderr, "oversized TLS template lost\n");
        return 1;
    }
    // ...while initial-exec to the same size must fail by name, not crash.
    if (stub_dlopen("libdlfcn-test-bigtlsie.so", RTLD_NOW | RTLD_LOCAL)) {
        fprintf(stderr, "oversized initial-exec TLS load succeeded\n");
        return 1;
    }
    auto* arenaError = stub_dlerror();
    if (!arenaError || !strstr(arenaError, "static TLS arena")) {
        fprintf(stderr, "oversized initial-exec failure lacks the arena message: %s\n", arenaError ? arenaError : "(null)");
        return 1;
    }

    // ld.so scope order: the global interposer beats a definition inside a
    // later image's own closure, RTLD_DEEPBIND flips that, and -Bsymbolic
    // pins an image's internal calls to its own definition.
    auto* interposer = stub_dlopen("libdlfcn-test-interpose.so", RTLD_NOW | RTLD_GLOBAL);
    if (!interposer) {
        fprintf(stderr, "interposer load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto interposerTag = reinterpret_cast<GlibcTest>(requiredSymbol(interposer, "dlfcn_interposer_tag"));
    if (!interposerTag || interposerTag() != 42) {
        fprintf(stderr, "interposer sanity check failed\n");
        return 1;
    }
    auto* caller = stub_dlopen("libdlfcn-test-caller.so", RTLD_NOW | RTLD_LOCAL);
    if (!caller) {
        fprintf(stderr, "caller load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto callOverridable = reinterpret_cast<GlibcTest>(requiredSymbol(caller, "dlfcn_call_overridable"));
    if (!callOverridable || callOverridable() != 2) {
        fprintf(stderr, "global scope did not interpose the closure definition\n");
        return 1;
    }
    auto* deepCaller = stub_dlopen("libdlfcn-test-callerdeep.so", RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
    if (!deepCaller) {
        fprintf(stderr, "deepbind caller load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto deepCall = reinterpret_cast<GlibcTest>(requiredSymbol(deepCaller, "dlfcn_call_overridable"));
    if (!deepCall || deepCall() != 1) {
        fprintf(stderr, "RTLD_DEEPBIND did not prefer the closure definition\n");
        return 1;
    }
    // The plain definition was relocated with the interposer global, so its
    // internal call is interposed; the -Bsymbolic build is pinned to itself.
    auto* plainDefinition = stub_dlopen("libdlfcn-test-overridable.so", RTLD_NOW | RTLD_LOCAL);
    auto* symbolicDefinition = stub_dlopen("libdlfcn-test-symbolic.so", RTLD_NOW | RTLD_LOCAL);
    if (!plainDefinition || !symbolicDefinition) {
        fprintf(stderr, "overridable definitions load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto plainViaSelf = reinterpret_cast<GlibcTest>(requiredSymbol(plainDefinition, "dlfcn_overridable_via_self"));
    auto symbolicViaSelf = reinterpret_cast<GlibcTest>(requiredSymbol(symbolicDefinition, "dlfcn_overridable_via_self"));
    if (!plainViaSelf || plainViaSelf() != 2) {
        fprintf(stderr, "plain image dodged the global interposer\n");
        return 1;
    }
    if (!symbolicViaSelf || symbolicViaSelf() != 1) {
        fprintf(stderr, "-Bsymbolic image did not bind to itself\n");
        return 1;
    }

    // A SysV-hash-only image: dlsym goes through the fallback lookup, and
    // its internal call is interposed like any other image's.
    auto* sysv = stub_dlopen("libdlfcn-test-sysv.so", RTLD_NOW | RTLD_LOCAL);
    if (!sysv) {
        fprintf(stderr, "SysV hash image load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto sysvViaSelf = reinterpret_cast<GlibcTest>(requiredSymbol(sysv, "dlfcn_overridable_via_self"));
    if (!sysvViaSelf || sysvViaSelf() != 2) {
        fprintf(stderr, "SysV hash lookup or interposition failed\n");
        return 1;
    }

    // The consumer's dlfcn_versioned_fn@V1 reference resolves against the
    // unversioned runtime provider, per ld.so's compatibility rule.
    auto* versionConsumer = stub_dlopen("libdlfcn-test-verconsumer.so", RTLD_NOW | RTLD_LOCAL);
    if (!versionConsumer) {
        fprintf(stderr, "versioned consumer load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto callVersioned = reinterpret_cast<GlibcTest>(requiredSymbol(versionConsumer, "dlfcn_call_versioned"));
    if (!callVersioned || callVersioned() != 7) {
        fprintf(stderr, "unversioned provider did not satisfy the versioned reference\n");
        return 1;
    }

    // On glibc hosts the harness picks a library only /etc/ld.so.cache can
    // resolve.
    if (const auto* cacheProbe = getenv("DLFCN_CACHE_PROBE"); cacheProbe && *cacheProbe) {
        if (!stub_dlopen(cacheProbe, RTLD_NOW | RTLD_LOCAL)) {
            fprintf(stderr, "ld.so.cache resolution of %s failed: %s\n", cacheProbe, stub_dlerror());
            return 1;
        }
    }

    // The conformance battery: one check per implemented bridge adapter.
    auto* shim = stub_dlopen("libdlfcn-test-shim.so", RTLD_NOW | RTLD_LOCAL);
    if (!shim) {
        fprintf(stderr, "shim conformance load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto shimTest = reinterpret_cast<GlibcTest>(requiredSymbol(shim, "glibc_shim_test"));
    if (!shimTest) {
        return 1;
    }
    if (auto result = shimTest(); result != 0) {
        fprintf(stderr, "glibc shim conformance failed: %d check(s)\n", result);
        return 1;
    }

    auto* glibcException = stub_dlopen("libdlfcn-test-exception.so", RTLD_NOW | RTLD_LOCAL);

    if (!glibcException) {
        fprintf(stderr, "glibc C++ exception test load failed: %s\n", stub_dlerror());
        return 1;
    }
    auto glibcThrowCatch = reinterpret_cast<GlibcTest>(requiredSymbol(glibcException, "glibc_test_exception"));
    foreignThrow = reinterpret_cast<GlibcThrow>(requiredSymbol(glibcException, "glibc_test_throw"));
    auto glibcCall = reinterpret_cast<GlibcCall>(requiredSymbol(glibcException, "glibc_test_call"));
    auto glibcCatch = reinterpret_cast<GlibcCatch>(requiredSymbol(glibcException, "glibc_test_catch"));
    auto glibcDestructions = reinterpret_cast<GlibcTest>(requiredSymbol(glibcException, "glibc_test_destructions"));
    auto glibcFindObject = reinterpret_cast<GlibcTest>(requiredSymbol(glibcException, "glibc_test_find_object"));

    if (!glibcThrowCatch || !foreignThrow || !glibcCall || !glibcCatch || !glibcDestructions || !glibcFindObject || glibcThrowCatch() != 42 || glibcFindObject() != 0) {
        fprintf(stderr, "glibc C++ exception propagation failed\n");
        return 1;
    }

    bool caught = false;
    try {
        foreignThrow();
    } catch (...) {
        caught = true;
    }
    if (!caught || glibcDestructions() != 1) {
        fprintf(stderr, "glibc exception did not unwind into the static world\n");
        return 1;
    }

    caught = false;
    try {
        glibcCall(throwFromStaticWorld);
    } catch (...) {
        caught = true;
    }
    if (!caught || glibcDestructions() != 2) {
        fprintf(stderr, "static exception did not unwind through the glibc world\n");
        return 1;
    }

    if (glibcCatch(throwFromStaticWorld) != 44 || glibcDestructions() != 3) {
        fprintf(stderr, "glibc catch (...) did not catch a static exception\n");
        return 1;
    }

    if (glibcCatch(throwForeignFromCallback) != 44 || glibcDestructions() != 5) {
        fprintf(stderr, "glibc exception did not cross a static callback into glibc catch (...)\n");
        return 1;
    }

    glibcCall(catchForeignInCallback);
    if (!callbackCaught || glibcDestructions() != 7) {
        fprintf(stderr, "static callback did not catch a glibc exception\n");
        return 1;
    }

    auto* pci = stub_dlopen("libdlfcn-test-pci.so", RTLD_NOW | RTLD_LOCAL);

    if (!pci) {
        fprintf(stderr, "recursive load failed: %s\n", stub_dlerror());
        return 1;
    }
    if (!stub_dlsym(pci, "pci_system_init")) {
        fprintf(stderr, "libpciaccess lookup failed: %s\n", stub_dlerror());
        return 1;
    }

    // The loader owns the returned image.
    ElfImage* image = nullptr;
    try {
        image = ElfImage::loadElf("libdlfcn-test-vulkan.so", RTLD_NOW | RTLD_LOCAL);
    } catch (const std::exception& error) {
        fprintf(stderr, "load failed: %s\n", error.what());
        return 1;
    }

    auto enumerate = reinterpret_cast<EnumerateInstanceVersion>(image->lookup("vkEnumerateInstanceVersion"));

    if (!enumerate) {
        fprintf(stderr, "symbol lookup failed\n");
        return 1;
    }

    Dl_info info = {};
    if (!stub_dladdr(reinterpret_cast<const void*>(enumerate), &info) || !info.dli_sname || strcmp(info.dli_sname, "vkEnumerateInstanceVersion") != 0 || info.dli_saddr != reinterpret_cast<void*>(enumerate)) {
        fprintf(stderr, "dladdr symbol resolution failed: %s %p\n", info.dli_sname ? info.dli_sname : "(null)", info.dli_saddr);
        return 1;
    }

    uint32_t version = 0;
    auto result = enumerate(&version);

    printf(
        "static libc provider: %zu symbols\n"
        "glibc dlopen/dlsym bridge: libc, libdl, pthread, factory, ELF, versions: ok\n"
        "file-backed segments named in /proc/self/maps: ok\n"
        "RTLD_GLOBAL and RTLD_NEXT: ok\n"
        "lazy PLT binding: ok\n"
        "initial-exec TLS: arena placement, both models, fresh and parked threads: ok\n"
        "scope order: global interposition, RTLD_DEEPBIND, -Bsymbolic: ok\n"
        "SysV hash, unversioned provider compat, ld.so.cache: ok\n"
        "glibc shim conformance battery: ok\n"
        "ELF TLS: per-thread blocks and thread-exit destructors: ok\n"
        "glibc C++ throw, unwind, destructor, catch: ok\n"
        "C++ exceptions across static/glibc boundaries in both directions: ok\n"
        "recursive DT_NEEDED: libpciaccess -> libz: ok\n"
        "vkEnumerateInstanceVersion: result=%d version=%u.%u.%u\n",
        symbols.count,
        result,
        version >> 22,
        (version >> 12) & 0x3ff,
        version & 0xfff
    );
    return result != 0;
}
