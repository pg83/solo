import json
import os
import shutil
import types

import build


build.cflags += [
    "-Wall",
    "-Wextra",
    "-O2",
    "-g",
]

build.cxxflags += [
    "-std=c++20",
]

build.flags.allow({
    "use_corpus": {
        "descr": "directory with pre-fetched package archives; downloads copy "
                 "from it and fall back to the network on a miss",
    },
})

cc = os.environ.get("CC", "cc")
# The first component of the target triple: musl arch directories, symbol
# inventories, and package pools all key off it.
machine = build.target.split("-")[0]

linker_flags = []

if shutil.which("ld") is None and (lld := shutil.which("ld.lld")):
    linker_flags.append(f"-fuse-ld={lld}")
if build.target != build.host:
    # Link steps invoke the compiler directly, outside the runner's compile
    # rules, so a cross build's target has to ride along here too.
    linker_flags.append(f"--target={build.target}")

# run_smoke.py links its glibc test DSOs with these commands directly, so they
# need the same linker selection as the graph's own link steps.
glibc_test_cc = " ".join([os.environ.get("GLIBC_TEST_CC", cc), *linker_flags])
glibc_test_cxx = " ".join([
    os.environ.get("GLIBC_TEST_CXX", os.environ.get("CXX", "c++")),
    *linker_flags,
])


def symbolHeader(kind):
    output = f"$(B)/lib/{kind}_symbols.json.h"

    return command(
        name=f"{kind}_symbols_header",
        inputs=[
            "$(S)/dev/generate_symbol_headers.py",
            f"$(S)/lib/{kind}_symbols_{machine}.json",
        ],
        outputs=[output],
        cmd=[
            "python3",
            "$(S)/dev/generate_symbol_headers.py",
            kind,
            f"$(S)/lib/{kind}_symbols_{machine}.json",
            output,
        ],
    )


musl_symbols_header = symbolHeader("musl")
glibc_symbols_header = symbolHeader("glibc")
symbol_headers = [musl_symbols_header, glibc_symbols_header]

dlfcn_srcs = [
    "$(S)/lib/bionic_shim.cpp",
    "$(S)/lib/dlfcn.cpp",
    "$(S)/lib/elf_loader.S",
    "$(S)/lib/elf_loader.cpp",
    "$(S)/lib/fts.cpp",
    "$(S)/lib/glibc_shim.S",
    "$(S)/lib/glibc_shim.cpp",
    "$(S)/lib/glibc_stubs.cpp",
    "$(S)/lib/hash.cpp",
    "$(S)/lib/iface_handle.cpp",
    "$(S)/lib/musl_provider.cpp",
    "$(S)/lib/musl_symbols.cpp",
    "$(S)/lib/musl_tls.c",
    "$(S)/lib/thread_tls.cpp",
]


def vendorPaths(root, names):
    return [f"{root}/{name}" for name in names]


def muslSources():
    root = "$(S)/bin/vulkan/musl"
    replacedDlfcn = {
        f"{root}/src/ldso/__dlsym.c",
        f"{root}/src/ldso/dladdr.c",
        f"{root}/src/ldso/dlclose.c",
        f"{root}/src/ldso/dlerror.c",
        f"{root}/src/ldso/dlinfo.c",
        f"{root}/src/ldso/dlopen.c",
        f"{root}/src/ldso/dlsym.c",
        f"{root}/src/ldso/{machine}/dlsym.s",
    }
    generic = [
        *build.glob(f"{root}/src/*/*.c"),
        *build.glob(f"{root}/src/malloc/mallocng/*.c"),
    ]
    architecture = [
        *build.glob(f"{root}/src/*/{machine}/*.[csS]"),
        *build.glob(f"{root}/src/malloc/mallocng/{machine}/*.[csS]"),
    ]
    replacements = {
        source.replace(f"/{machine}/", "/").rsplit(".", 1)[0]
        for source in architecture
    }
    return [
        source for source in generic
        if source not in replacedDlfcn and source.rsplit(".", 1)[0] not in replacements
    ] + [
        source for source in architecture
        if source not in replacedDlfcn
    ]


vulkan_root = "$(S)/bin/vulkan"
musl_root = f"{vulkan_root}/musl"
llvm_root = f"{vulkan_root}/llvm"
libcxx_root = f"{llvm_root}/libcxx"
libcxxabi_root = f"{llvm_root}/libcxxabi"
libunwind_root = f"{llvm_root}/libunwind"
compiler_rt_root = f"{llvm_root}/compiler-rt/builtins"
vulkan_headers_root = f"{vulkan_root}/vulkan/headers/include"
vulkan_loader_root = f"{vulkan_root}/vulkan/loader/loader"

# The tests and the vulkan demo link the vendored musl and libc++; the host
# library must never see those headers. Include paths are therefore per-target:
# every vendored target lists this set, and the host targets resolve against
# the host toolchain alone, so one invocation can build both worlds.
vendored_includes = [
    "$(S)/lib",
    "$(B)/bin/vulkan/libcxx/include",
    f"{libcxx_root}/include",
    f"{libcxxabi_root}/include",
    f"{libunwind_root}/include",
    f"{musl_root}/arch/{machine}",
    f"{musl_root}/arch/generic",
    "$(B)/bin/vulkan/musl/include",
    f"{musl_root}/include",
    f"{compiler_rt_root}",
    f"{libcxx_root}/src",
    f"{libcxx_root}/src/include",
    f"{libcxxabi_root}/src",
    f"{libunwind_root}/src",
    "$(B)/bin/vulkan/zlib",
    f"{vulkan_root}/zlib",
    "$(B)/bin/vulkan/png",
    f"{vulkan_root}/png",
    f"{vulkan_loader_root}",
    f"{vulkan_loader_root}/generated",
    f"{vulkan_headers_root}",
    f"{vulkan_root}",
]

musl_internal_includes = [
    f"{musl_root}/arch/{machine}",
    f"{musl_root}/arch/generic",
    "$(B)/bin/vulkan/musl/internal",
    f"{musl_root}/src/include",
    f"{musl_root}/src/internal",
    "$(B)/bin/vulkan/musl/include",
    f"{musl_root}/include",
]

# What lib/musl_tls.c needs on the include path: the per-architecture headers
# pthread_impl.h pulls in, and the public musl headers. Its src/internal home
# is reached by relative path from musl_tls.c itself and must never be listed
# here — musl's private headers shadow public names (syscall.h, atomic.h),
# and the loader's C++ sources share these paths.
musl_private_includes = [
    f"{musl_root}/arch/{machine}",
    f"{musl_root}/arch/generic",
    "$(B)/bin/vulkan/musl/include",
    f"{musl_root}/include",
]

musl_alltypes = command(
    inputs=[
        f"{vulkan_root}/generate.py",
        f"{musl_root}/arch/{machine}/bits/alltypes.h.in",
        f"{musl_root}/include/alltypes.h.in",
    ],
    outputs=["$(B)/bin/vulkan/musl/include/bits/alltypes.h"],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "alltypes",
        "$(B)/bin/vulkan/musl/include/bits/alltypes.h",
        f"{musl_root}/arch/{machine}/bits/alltypes.h.in",
        f"{musl_root}/include/alltypes.h.in",
    ],
)

musl_syscall = command(
    inputs=[
        f"{vulkan_root}/generate.py",
        f"{musl_root}/arch/{machine}/bits/syscall.h.in",
    ],
    outputs=["$(B)/bin/vulkan/musl/include/bits/syscall.h"],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "syscall",
        "$(B)/bin/vulkan/musl/include/bits/syscall.h",
        f"{musl_root}/arch/{machine}/bits/syscall.h.in",
    ],
)

musl_version = command(
    inputs=[f"{vulkan_root}/generate.py", f"{musl_root}/VERSION"],
    outputs=["$(B)/bin/vulkan/musl/internal/version.h"],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "version",
        "$(B)/bin/vulkan/musl/internal/version.h",
        f"{musl_root}/VERSION",
    ],
)

libcxx_config_path = "$(B)/bin/vulkan/libcxx/include/__config_site"
libcxx_config = command(
    inputs=[
        f"{vulkan_root}/generate.py",
        f"{libcxx_root}/include/__config_site.in",
    ],
    outputs=[libcxx_config_path],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "libcxx-config",
        "$(B)/bin/vulkan/libcxx/include/__config_site",
        f"{libcxx_root}/include/__config_site.in",
    ],
)

runtime_generated = [
    musl_alltypes,
    musl_syscall,
    musl_version,
    libcxx_config,
]

dlfcn = library(
    srcs=dlfcn_srcs,
    deps=[*symbol_headers, musl_alltypes, musl_syscall, musl_version],
    includes=["$(B)/lib", *musl_private_includes],
    cppflags=["-DCOMPILE_DLOPEN", "-D_GNU_SOURCE"],
    public_cppflags=["-I$(S)/lib"],
    output="$(B)/libdlfcn.a",
)
target_flags = [
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-stack-protector",
    "-fno-omit-frame-pointer",
]
if machine == "aarch64":
    # The static world links no libgcc, so the LSE outline-atomic helpers
    # have no provider; inline LL/SC atomics need none.
    target_flags.append("-mno-outline-atomics")
c_runtime_flags = [
    *target_flags,
    "-nostdinc",
]
cxx_runtime_flags = [
    "-std=c++23",
    "-nostdinc++",
]

compiler_rt_sources = [
    source for source in build.glob(f"{compiler_rt_root}/*.c")
    if not source.rsplit("/", 1)[1].startswith(("atomic", "crtbegin", "crtend"))
]

libcxx_sources = vendorPaths(
    f"{libcxx_root}/src",
    [
        "algorithm.cpp",
        "any.cpp",
        "bind.cpp",
        "chrono.cpp",
        "exception.cpp",
        "functional.cpp",
        "hash.cpp",
        "legacy_pointer_safety.cpp",
        "memory.cpp",
        "optional.cpp",
        "random_shuffle.cpp",
        "ryu/d2fixed.cpp",
        "ryu/d2s.cpp",
        "ryu/f2s.cpp",
        "stdexcept.cpp",
        "string.cpp",
        "system_error.cpp",
        "typeinfo.cpp",
        "utility.cpp",
        "valarray.cpp",
        "variant.cpp",
        "vector.cpp",
        "verbose_abort.cpp",
        "barrier.cpp",
        "condition_variable_destructor.cpp",
        "condition_variable.cpp",
        "future.cpp",
        "mutex_destructor.cpp",
        "mutex.cpp",
        "shared_mutex.cpp",
        "thread.cpp",
        "random.cpp",
        "ios.cpp",
        "ios.instantiations.cpp",
        "iostream.cpp",
        "locale.cpp",
        "regex.cpp",
        "strstream.cpp",
        "new.cpp",
    ],
)
# One flavor of the vendored runtime the static executables link: the vulkan
# proof and the tests use the plain build, the solo command its own
# position-independent build for a static-PIE image. Nothing is shared
# between flavors but the sources and the generated headers.
def runtimeArchives(flavor, out, model_flags):
    flags = [*c_runtime_flags, *model_flags]
    musl = library(
        name=f"{flavor}_musl",
        srcs=muslSources(),
        deps=runtime_generated,
        includes=[*musl_internal_includes, *vendored_includes],
        cflags=[
            *flags,
            "-std=c99",
            "-ffreestanding",
            "-w",
        ],
        cppflags=["-D_XOPEN_SOURCE=700"],
        output=f"{out}/lib/libc.a",
    )
    compiler_rt = library(
        name=f"{flavor}_compiler_rt",
        srcs=compiler_rt_sources,
        deps=runtime_generated,
        includes=vendored_includes,
        cflags=[*flags, "-ffreestanding", "-w"],
        output=f"{out}/lib/libcompiler_rt.a",
    )
    libunwind = library(
        name=f"{flavor}_libunwind",
        srcs=vendorPaths(
            f"{libunwind_root}/src",
            [
                "libunwind.cpp",
                "Unwind-EHABI.cpp",
                "Unwind-seh.cpp",
                "UnwindLevel1.c",
                "UnwindLevel1-gcc-ext.c",
                "Unwind-sjlj.c",
                "UnwindRegistersRestore.S",
                "UnwindRegistersSave.S",
            ],
        ),
        deps=runtime_generated,
        includes=vendored_includes,
        cflags=[*flags, "-fexceptions", "-w"],
        cxxflags=[*cxx_runtime_flags, "-fno-rtti"],
        cppflags=[
            "-D_LIBUNWIND_IS_NATIVE_ONLY",
            "-D_LIBUNWIND_USE_DLADDR=0",
        ],
        output=f"{out}/lib/libunwind.a",
    )
    libcxxabi = library(
        name=f"{flavor}_libcxxabi",
        srcs=vendorPaths(
            f"{libcxxabi_root}/src",
            [
                "cxa_aux_runtime.cpp",
                "cxa_default_handlers.cpp",
                "cxa_demangle.cpp",
                "cxa_exception_storage.cpp",
                "cxa_guard.cpp",
                "cxa_handlers.cpp",
                "cxa_vector.cpp",
                "cxa_virtual.cpp",
                "stdlib_exception.cpp",
                "stdlib_stdexcept.cpp",
                "stdlib_typeinfo.cpp",
                "abort_message.cpp",
                "fallback_malloc.cpp",
                "private_typeinfo.cpp",
                "stdlib_new_delete.cpp",
                "cxa_exception.cpp",
                "cxa_personality.cpp",
                "cxa_thread_atexit.cpp",
            ],
        ),
        deps=runtime_generated,
        includes=vendored_includes,
        cflags=[*flags, "-w"],
        cxxflags=cxx_runtime_flags,
        cppflags=[
            "-D_LIBCXXABI_BUILDING_LIBRARY",
            "-D_LIBCPP_ENABLE_CXX17_REMOVED_UNEXPECTED_FUNCTIONS",
        ],
        output=f"{out}/lib/libc++abi.a",
    )
    libcxx = library(
        name=f"{flavor}_libcxx",
        srcs=libcxx_sources,
        deps=runtime_generated,
        includes=vendored_includes,
        cflags=[*flags, "-w"],
        cxxflags=cxx_runtime_flags,
        cppflags=[
            "-D_LIBCPP_BUILDING_LIBRARY",
            "-DLIBCXX_BUILDING_LIBCXXABI",
        ],
        output=f"{out}/lib/libc++.a",
    )
    dlfcn = library(
        name=f"{flavor}_dlfcn",
        srcs=dlfcn_srcs,
        deps=[*runtime_generated, *symbol_headers],
        includes=["$(B)/lib", *vendored_includes, *musl_private_includes],
        cflags=flags,
        cxxflags=[
            *cxx_runtime_flags,
            "-Wno-bitwise-op-parentheses",
            "-Wno-shift-op-parentheses",
        ],
        cppflags=["-DCOMPILE_DLOPEN", "-D_GNU_SOURCE"],
        output=f"{out}/lib/libdlfcn.a",
    )

    return types.SimpleNamespace(
        musl=musl,
        compiler_rt=compiler_rt,
        libunwind=libunwind,
        libcxxabi=libcxxabi,
        libcxx=libcxx,
        dlfcn=dlfcn,
    )


vulkan_runtime = runtimeArchives("vulkan", "$(B)/bin/vulkan", [])
solo_runtime = runtimeArchives("solo", "$(B)/bin/solo", ["-fPIE"])

zconf = command(
    name="vulkan_zconf",
    inputs=[f"{vulkan_root}/zlib/zconf.h.in"],
    outputs=["$(B)/bin/vulkan/zlib/zconf.h"],
    cmd=[
        "cp",
        f"{vulkan_root}/zlib/zconf.h.in",
        "$(B)/bin/vulkan/zlib/zconf.h",
    ],
)

zlib = library(
    name="vulkan_zlib",
    srcs=[
        {
            "src": source,
            "inputs": [
                "$(B)/bin/vulkan/musl/include/bits/alltypes.h",
                libcxx_config_path,
                "$(B)/bin/vulkan/zlib/zconf.h",
            ],
        }
        for source in vendorPaths(
            f"{vulkan_root}/zlib",
            [
                "adler32.c",
                "compress.c",
                "crc32.c",
                "deflate.c",
                "gzclose.c",
                "gzlib.c",
                "gzread.c",
                "gzwrite.c",
                "inflate.c",
                "infback.c",
                "inftrees.c",
                "inffast.c",
                "trees.c",
                "uncompr.c",
                "zutil.c",
            ],
        )
    ],
    deps=[*runtime_generated, zconf],
    includes=vendored_includes,
    cflags=[*c_runtime_flags, "-w"],
    cppflags=["-DHAVE_UNISTD_H=1"],
    output="$(B)/bin/vulkan/lib/libz.a",
)

pnglibconf_path = "$(B)/bin/vulkan/png/pnglibconf.h"
pnglibconf = command(
    name="vulkan_pnglibconf",
    inputs=[f"{vulkan_root}/png/scripts/pnglibconf.h.prebuilt"],
    outputs=[pnglibconf_path],
    cmd=[
        "cp",
        f"{vulkan_root}/png/scripts/pnglibconf.h.prebuilt",
        pnglibconf_path,
    ],
)

png = library(
    name="vulkan_png",
    srcs=[
        {
            "src": source,
            "inputs": [
                libcxx_config_path,
                pnglibconf_path,
            ],
        }
        for source in vendorPaths(
            f"{vulkan_root}/png",
            [
                "png.c",
                "pngerror.c",
                "pngget.c",
                "pngmem.c",
                "pngpread.c",
                "pngread.c",
                "pngrio.c",
                "pngrtran.c",
                "pngrutil.c",
                "pngset.c",
                "pngtrans.c",
                "pngwio.c",
                "pngwrite.c",
                "pngwtran.c",
                "pngwutil.c",
            ],
        )
    ],
    deps=[*runtime_generated, pnglibconf],
    includes=vendored_includes,
    cflags=[*c_runtime_flags, "-w"],
    # The NEON filter paths want the compiler's arm_neon.h, which -nostdinc
    # hides; the demo writes one PNG, so plain C paths are plenty.
    cppflags=["-DPNG_ARM_NEON_OPT=0"] if machine == "aarch64" else [],
    output="$(B)/bin/vulkan/lib/libpng.a",
)

vulkan_loader = library(
    name="vulkan_loader",
    srcs=vendorPaths(
        vulkan_loader_root,
        [
            "allocation.c",
            "cJSON.c",
            "debug_utils.c",
            "extension_manual.c",
            "loader_environment.c",
            "gpa_helper.c",
            "loader.c",
            "log.c",
            "loader_json.c",
            "settings.c",
            "terminator.c",
            "trampoline.c",
            "unknown_function_handling.c",
            "wsi.c",
            "loader_linux.c",
        ],
    ),
    deps=runtime_generated,
    includes=vendored_includes,
    cflags=[*c_runtime_flags, "-w"],
    cppflags=[
        "-D_GNU_SOURCE",
        "-DHAVE_ALLOCA_H",
        "-DHAVE_REALPATH",
        "-DHAVE_SECURE_GETENV",
        "-DLOADER_ENABLE_LINUX_SORT",
        "-DVK_ENABLE_BETA_EXTENSIONS",
        '-DSYSCONFDIR="/etc"',
        # NixOS has no /usr/share; its graphics drivers publish their ICD
        # manifests under /run/opengl-driver/share, and nixpkgs teaches its
        # own vulkan-loader that path the same way. Scanned unconditionally,
        # harmless where the directory does not exist.
        '-DEXTRASYSCONFDIR="/run/opengl-driver/share"',
        '-DFALLBACK_CONFIG_DIRS="/etc/xdg"',
        '-DFALLBACK_DATA_DIRS="/usr/local/share:/usr/share"',
    ],
    output="$(B)/bin/vulkan/lib/libvulkan.a",
)

vulkan_app = library(
    name="vulkan_app",
    srcs=[
        {
            "src": f"{vulkan_root}/main.cpp",
            "inputs": [
                libcxx_config_path,
                pnglibconf_path,
            ],
        },
    ],
    deps=[*runtime_generated, pnglibconf],
    includes=vendored_includes,
    cflags=c_runtime_flags,
    cxxflags=cxx_runtime_flags,
    output="$(B)/bin/vulkan/lib/libvulkan_app.a",
)


def muslCrt(flavor, name, source, out, model_flags):
    return library(
        name=f"{flavor}_{name}",
        srcs=[source],
        deps=runtime_generated,
        includes=[*musl_internal_includes, *vendored_includes],
        cflags=[
            *target_flags,
            *model_flags,
            "-w",
            "-nostdinc",
            "-DCRT",
        ],
        output=f"{out}/crt/lib{name}.a",
    )


vulkan_crt1 = muslCrt("vulkan", "crt1", f"{musl_root}/crt/crt1.c", "$(B)/bin/vulkan", [])
vulkan_crti = muslCrt("vulkan", "crti", f"{musl_root}/crt/{machine}/crti.s", "$(B)/bin/vulkan", [])
vulkan_crtn = muslCrt("vulkan", "crtn", f"{musl_root}/crt/{machine}/crtn.s", "$(B)/bin/vulkan", [])
vulkan_crtend = muslCrt("vulkan", "crtend", "$(S)/lib/crtend.s", "$(B)/bin/vulkan", [])

vulkan_archives = [
    vulkan_app,
    vulkan_loader,
    vulkan_runtime.dlfcn,
    png,
    zlib,
    vulkan_runtime.libcxx,
    vulkan_runtime.libcxxabi,
    vulkan_runtime.libunwind,
    vulkan_runtime.musl,
    vulkan_runtime.compiler_rt,
]
vulkan = command(
    name="vulkan",
    inputs=[
        vulkan_crt1.output,
        vulkan_crti.output,
        vulkan_crtn.output,
        vulkan_crtend.output,
        *[archive.output for archive in vulkan_archives],
    ],
    outputs=["$(B)/bin/vulkan/vulkan"],
    deps=[vulkan_crt1, vulkan_crti, vulkan_crtn, vulkan_crtend, *vulkan_archives],
    cmd=[
        cc,
        *linker_flags,
        "-nostdlib",
        "-static",
        "-Wl,--no-pie",
        # GCC's LINK_EH_SPEC drops --eh-frame-hdr for -static, expecting crtbegin
        # to register frames; our libunwind finds them through PT_GNU_EH_FRAME.
        "-Wl,--eh-frame-hdr",
        "-Wl,--build-id=none",
        "-Wl,--gc-sections",
        "-Wl,-z,noexecstack",
        "-Wl,-e,_start",
        "-o",
        "$(B)/bin/vulkan/vulkan",
        "-Wl,--whole-archive",
        vulkan_crti.output,
        vulkan_crt1.output,
        "-Wl,--no-whole-archive",
        "-Wl,--start-group",
        "-Wl,--whole-archive",
        vulkan_app.output,
        "-Wl,--no-whole-archive",
        *[archive.output for archive in vulkan_archives[1:]],
        "-Wl,--end-group",
        "-Wl,--whole-archive",
        vulkan_crtn.output,
        vulkan_crtend.output,
        "-Wl,--no-whole-archive",
    ],
    descr="LD",
    color="light-blue",
)


def vendoredTest(name, source):
    application = library(
        name=f"{name}_app",
        srcs=[{"src": source, "inputs": [libcxx_config_path]}],
        deps=[*runtime_generated, *symbol_headers],
        includes=["$(B)/lib", *vendored_includes],
        cflags=c_runtime_flags,
        cxxflags=cxx_runtime_flags,
        output=f"$(B)/tst/lib/lib{name}_app.a",
    )
    archives = [
        application,
        vulkan_runtime.dlfcn,
        vulkan_runtime.libcxx,
        vulkan_runtime.libcxxabi,
        vulkan_runtime.libunwind,
        vulkan_runtime.musl,
        vulkan_runtime.compiler_rt,
    ]

    return command(
        name=name,
        inputs=[
            vulkan_crt1.output,
            vulkan_crti.output,
            vulkan_crtn.output,
            vulkan_crtend.output,
            *[archive.output for archive in archives],
        ],
        outputs=[f"$(B)/tst/{name}"],
        deps=[vulkan_crt1, vulkan_crti, vulkan_crtn, vulkan_crtend, *archives],
        cmd=[
            cc,
            *linker_flags,
            "-nostdlib",
            "-static",
            "-Wl,--no-pie",
            "-Wl,--eh-frame-hdr",
            "-Wl,--build-id=none",
            "-Wl,--gc-sections",
            "-Wl,-z,noexecstack",
            "-Wl,-e,_start",
            "-o",
            f"$(B)/tst/{name}",
            "-Wl,--whole-archive",
            vulkan_crti.output,
            vulkan_crt1.output,
            "-Wl,--no-whole-archive",
            "-Wl,--start-group",
            "-Wl,--whole-archive",
            application.output,
            "-Wl,--no-whole-archive",
            *[archive.output for archive in archives[1:]],
            "-Wl,--end-group",
            "-Wl,--whole-archive",
            vulkan_crtn.output,
            vulkan_crtend.output,
            "-Wl,--no-whole-archive",
        ],
        descr="LD",
        color="light-blue",
    )


smoke = vendoredTest("smoke", "$(S)/tst/smoke.cpp")
pthread_bridge = vendoredTest("pthread_bridge", "$(S)/tst/pthread_bridge.cpp")

# The solo command: `solo run ./app` executes a ready-made glibc binary over
# the bridge, `solo ldd ./app` prints its closure. Its own runtime flavor,
# linked static-PIE with musl's self-relocating rcrt1, so the image stays out
# of the fixed addresses non-PIE guests own; nothing of the vulkan world is
# in it.
solo_rcrt1 = muslCrt("solo", "rcrt1", f"{musl_root}/crt/rcrt1.c", "$(B)/bin/solo", ["-fPIE"])
solo_crti = muslCrt("solo", "crti", f"{musl_root}/crt/{machine}/crti.s", "$(B)/bin/solo", ["-fPIE"])
solo_crtn = muslCrt("solo", "crtn", f"{musl_root}/crt/{machine}/crtn.s", "$(B)/bin/solo", ["-fPIE"])
solo_crtend = muslCrt("solo", "crtend", "$(S)/lib/crtend.s", "$(B)/bin/solo", ["-fPIE"])

solo_app = library(
    name="solo_app",
    srcs=[{"src": "$(S)/bin/solo/main.cpp", "inputs": [libcxx_config_path]}],
    deps=[*runtime_generated, *symbol_headers],
    includes=["$(B)/lib", *vendored_includes],
    cflags=[*c_runtime_flags, "-fPIE"],
    cxxflags=cxx_runtime_flags,
    output="$(B)/bin/solo/lib/libsolo_app.a",
)
solo_archives = [
    solo_app,
    solo_runtime.dlfcn,
    solo_runtime.libcxx,
    solo_runtime.libcxxabi,
    solo_runtime.libunwind,
    solo_runtime.musl,
    solo_runtime.compiler_rt,
]
solo_cli = command(
    name="solo",
    inputs=[
        solo_rcrt1.output,
        solo_crti.output,
        solo_crtn.output,
        solo_crtend.output,
        *[archive.output for archive in solo_archives],
    ],
    outputs=["$(B)/bin/solo/solo"],
    deps=[solo_rcrt1, solo_crti, solo_crtn, solo_crtend, *solo_archives],
    cmd=[
        cc,
        *linker_flags,
        "-nostdlib",
        "-static-pie",
        "-Wl,--eh-frame-hdr",
        "-Wl,--build-id=none",
        "-Wl,--gc-sections",
        "-Wl,-z,noexecstack",
        "-Wl,-e,_start",
        "-o",
        "$(B)/bin/solo/solo",
        "-Wl,--whole-archive",
        solo_crti.output,
        solo_rcrt1.output,
        "-Wl,--no-whole-archive",
        "-Wl,--start-group",
        "-Wl,--whole-archive",
        solo_app.output,
        "-Wl,--no-whole-archive",
        *[archive.output for archive in solo_archives[1:]],
        "-Wl,--end-group",
        "-Wl,--whole-archive",
        solo_crtn.output,
        solo_crtend.output,
        "-Wl,--no-whole-archive",
    ],
    descr="LD",
    color="light-blue",
)

pthread_test = command(
    name="pthread_test",
    inputs=["$(S)/tst/run_pthread_bridge.py"],
    outputs=["$(B)/tst/pthread-bridge.log"],
    deps=[pthread_bridge],
    cmd=[
        "python3",
        "$(S)/tst/run_pthread_bridge.py",
        "$(B)/tst/pthread_bridge",
        "$(B)/tst/pthread-bridge.log",
    ],
    descr="TS",
    color="green",
)

vulkan_test = command(
    name="vulkan_test",
    inputs=["$(S)/tst/run_vulkan.py"],
    outputs=["$(B)/tst/lavapipe.png"],
    deps=[vulkan],
    cmd=[
        "python3",
        "$(S)/tst/run_vulkan.py",
        "$(B)/bin/vulkan/vulkan",
        f"/usr/share/vulkan/icd.d/lvp_icd.{machine}.json",
        "$(B)/tst/lavapipe.png",
    ],
    descr="TS",
    color="green",
)

secure_probe = vendoredTest("secure_probe", "$(S)/tst/secure_probe.cpp")

secure_target = command(
    name="secure_target",
    inputs=["$(S)/tst/secure_target.c"],
    outputs=["$(B)/tst/libdlfcn-secure-target.so"],
    cmd=[
        cc,
        *linker_flags,
        "-shared",
        "-fPIC",
        "-nostdlib",
        "-fno-stack-protector",
        "-o",
        "$(B)/tst/libdlfcn-secure-target.so",
        "$(S)/tst/secure_target.c",
    ],
    descr="LD",
    color="light-blue",
)

secure_test = command(
    name="secure_test",
    inputs=["$(S)/tst/run_secure.py"],
    outputs=["$(B)/tst/secure.log"],
    deps=[secure_probe, secure_target],
    cmd=[
        "python3",
        "$(S)/tst/run_secure.py",
        "$(B)/tst/secure.log",
        "$(B)/tst/secure_probe",
        "$(B)/tst/libdlfcn-secure-target.so",
    ],
    descr="TS",
    color="green",
)

bionic_test = command(
    name="bionic_test",
    inputs=["$(S)/tst/run_bionic.py", "$(S)/tst/run_vulkan.py"],
    outputs=["$(B)/tst/bionic-lavapipe.png"],
    deps=[vulkan],
    cmd=[
        "python3",
        "$(S)/tst/run_bionic.py",
        "$(B)/bin/vulkan/vulkan",
        "$(B)/tst/bionic-lavapipe.png",
    ],
    descr="TS",
    color="green",
)

# The smoke sysroot: Arch pins on x86-64, the corpus's Debian snapshot on
# aarch64 (Arch Linux ARM keeps no archive), under one set of logical
# names. The sysroot layout differs, so run_smoke.py gets the library and
# include directories from the environment.
if machine == "x86_64":
    arch_packages = [
        (
            "glibc",
            "https://archive.archlinux.org/packages/g/glibc/"
            "glibc-2.44+r24+g16be1518495f-1-x86_64.pkg.tar.zst",
            "glibc-2.44+r24+g16be1518495f-1-x86_64.pkg.tar.zst",
            "5db2283f5b46b6114d06b4bc71fcf8ede5f1a04fcccb4d307048fcdc4e501d93",
        ),
        (
            "vulkan-icd-loader",
            "https://archive.archlinux.org/packages/v/vulkan-icd-loader/"
            "vulkan-icd-loader-1.4.357.0-1-x86_64.pkg.tar.zst",
            "vulkan-icd-loader-1.4.357.0-1-x86_64.pkg.tar.zst",
            "9ed4c22afb7ec3204dc13e8714d8144d43926b8c6d0d8299e6b95215569cd499",
        ),
        (
            "libpciaccess",
            "https://archive.archlinux.org/packages/l/libpciaccess/"
            "libpciaccess-0.19-1-x86_64.pkg.tar.zst",
            "libpciaccess-0.19-1-x86_64.pkg.tar.zst",
            "ef533895e7688da61749bee185103435dbe635d9773d092fb0516e132817e39f",
        ),
        (
            "zlib",
            "https://archive.archlinux.org/packages/z/zlib/"
            "zlib-1:1.3.2-3-x86_64.pkg.tar.zst",
            "zlib-1:1.3.2-3-x86_64.pkg.tar.zst",
            "41cf0bb5df14e18f7fb868a97da3feb7c4127fba99bb332ad54b14322faac1b1",
        ),
        (
            "libgcc",
            "https://archive.archlinux.org/packages/l/libgcc/"
            "libgcc-15.2.1%2Br604%2Bg0b99615a8aef-1-x86_64.pkg.tar.zst",
            "libgcc-15.2.1+r604+g0b99615a8aef-1-x86_64.pkg.tar.zst",
            "00ebc06ef4b8ff5c1fd7bd7b6faafdc7c3bfa7f1f3a170ff2f2025d1f0b62ace",
        ),
        (
            "libstdcxx",
            "https://archive.archlinux.org/packages/l/libstdc%2B%2B/"
            "libstdc%2B%2B-15.2.1%2Br604%2Bg0b99615a8aef-1-x86_64.pkg.tar.zst",
            "libstdc++-15.2.1+r604+g0b99615a8aef-1-x86_64.pkg.tar.zst",
            "73dc1b0000e915339759d9492bb30e93ff343e041d5d5601b2befda12235ec78",
        ),
        (
            "linux-api-headers",
            "https://archive.archlinux.org/packages/l/linux-api-headers/"
            "linux-api-headers-7.2-1-x86_64.pkg.tar.zst",
            "linux-api-headers-7.2-1-x86_64.pkg.tar.zst",
            "d8d3483363e70b353ae31bbf8773df77780724eaeaa140faf4e4111bdb87588f",
        ),
    ]
    sysroot_lib = "usr/lib"
    sysroot_includes = "usr/include"
else:
    arch_packages = [
        (
            "glibc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/glibc/"
            "libc6_2.42-17_arm64.deb",
            "smoke-libc6_2.42-17_arm64.deb",
            "1426f09ab5a533b38eb6a1b462cb9df9ac2b3f82fc4d570d19d9f7789e7bc96d",
        ),
        (
            "glibc-headers",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/glibc/"
            "libc6-dev_2.42-17_arm64.deb",
            "smoke-libc6-dev_2.42-17_arm64.deb",
            "d209f637c7c0015c26794841f1af5735ea802db4461a90a5d9be1bedda53d25b",
        ),
        (
            "linux-api-headers",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/linux/"
            "linux-libc-dev_7.1.5-1_all.deb",
            "smoke-linux-libc-dev_7.1.5-1_all.deb",
            "a02af1b1e76dc4d5f8945ba6e902ab3ffbfc5a2e4f92f79ab140ccc86c9c93e1",
        ),
        (
            "vulkan-icd-loader",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/v/vulkan-loader/"
            "libvulkan1_1.4.341.0-1_arm64.deb",
            "smoke-libvulkan1_1.4.341.0-1_arm64.deb",
            "361c65aa888c61a73b6f809ec85555fd07b9f5feab8e884abc12b1dae39b3be1",
        ),
        (
            "libpciaccess",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libp/libpciaccess/"
            "libpciaccess0_0.19-2_arm64.deb",
            "smoke-libpciaccess0_0.19-2_arm64.deb",
            "95391b93af12e6fc115f9ff52e1dff4a4e68ec2634070b6c532df4edba01b516",
        ),
        (
            "zlib",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/z/zlib/"
            "zlib1g_1.3.dfsg+really1.3.2-3_arm64.deb",
            "smoke-zlib1g_1.3.dfsg+really1.3.2-3_arm64.deb",
            "a77a1a137da4f6e440fa638b00a60dc3d7124e9678402ea5335bc02e75bf267e",
        ),
        (
            "libgcc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libgcc-s1_16.1.0-3_arm64.deb",
            "smoke-libgcc-s1_16.1.0-3_arm64.deb",
            "f5e30fd43af507b7674cac5f776b97db0a0ae5f97c6ec0103c828e15060a7f95",
        ),
        (
            "libstdcxx",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libstdc++6_16.1.0-3_arm64.deb",
            "smoke-libstdc++6_16.1.0-3_arm64.deb",
            "837c4a9d01e2aff0866264e1d90ae25775c90e5262beec9b36dc9a088eb3938f",
        ),
    ]
    sysroot_lib = "usr/lib/aarch64-linux-gnu"
    sysroot_includes = "usr/include:usr/include/aarch64-linux-gnu"

downloadTargets = {}
downloadOutputs = {}


def downloadPackage(name, url, filename, sha256):
    output = downloadOutputs[name] = f"$(B)/tst/packages/{filename}"

    downloadTargets[name] = command(
        name=f"download_{name}",
        inputs=["$(S)/tst/download.py"],
        outputs=[output],
        cmd=[
            "python3",
            "$(S)/tst/download.py",
            *(["--mirror", build.flags.use_corpus] if build.flags.use_corpus else []),
            url,
            sha256,
            output,
        ],
        descr="DL",
        color="cyan",
    )

    return output


archives = [downloadPackage(*package) for package in arch_packages]
downloads = list(downloadTargets.values())

arch_smoke = command(
    name="arch_smoke",
    inputs=["$(S)/tst/glibc_test.c", "$(S)/tst/glibc_exception_test.cpp", "$(S)/tst/glibc_lazy_test.c", "$(S)/tst/glibc_shim_test.c", "$(S)/tst/glibc_ie_test.c", "$(S)/tst/glibc_interpose_test.c", "$(S)/tst/glibc_overridable_test.c", "$(S)/tst/glibc_caller_test.c", "$(S)/tst/glibc_versioned_test.c", "$(S)/tst/glibc_version_consumer_test.c", "$(S)/tst/glibc_ie_gd_test.c", "$(S)/tst/glibc_ie_ref_test.c", "$(S)/tst/glibc_big_tls_test.c", "$(S)/tst/glibc_runpath_host_test.c", "$(S)/tst/glibc_runpath_sibling_test.c", "$(S)/tst/glibc_guest_test.c", "$(S)/tst/run_smoke.py", *archives],
    outputs=["$(B)/tst/arch-smoke.log"],
    deps=[smoke, solo_cli, *downloads],
    cmd=[
        "python3",
        "$(S)/tst/run_smoke.py",
        "$(B)/tst/arch-smoke.log",
        *archives,
    ],
    env={
        "DLFCN_CC": glibc_test_cc,
        "DLFCN_CXX": glibc_test_cxx,
        "DLFCN_GLIBC_EXCEPTION_TEST_SOURCE": "$(S)/tst/glibc_exception_test.cpp",
        "DLFCN_GLIBC_LAZY_TEST_SOURCE": "$(S)/tst/glibc_lazy_test.c",
        "DLFCN_GLIBC_SHIM_TEST_SOURCE": "$(S)/tst/glibc_shim_test.c",
        "DLFCN_GLIBC_IE_TEST_SOURCE": "$(S)/tst/glibc_ie_test.c",
        "DLFCN_GLIBC_INTERPOSE_TEST_SOURCE": "$(S)/tst/glibc_interpose_test.c",
        "DLFCN_GLIBC_OVERRIDABLE_TEST_SOURCE": "$(S)/tst/glibc_overridable_test.c",
        "DLFCN_GLIBC_CALLER_TEST_SOURCE": "$(S)/tst/glibc_caller_test.c",
        "DLFCN_GLIBC_VERSIONED_TEST_SOURCE": "$(S)/tst/glibc_versioned_test.c",
        "DLFCN_GLIBC_VERSION_CONSUMER_TEST_SOURCE": "$(S)/tst/glibc_version_consumer_test.c",
        "DLFCN_GLIBC_IE_GD_TEST_SOURCE": "$(S)/tst/glibc_ie_gd_test.c",
        "DLFCN_GLIBC_IE_REF_TEST_SOURCE": "$(S)/tst/glibc_ie_ref_test.c",
        "DLFCN_GLIBC_BIG_TLS_TEST_SOURCE": "$(S)/tst/glibc_big_tls_test.c",
        "DLFCN_GLIBC_RUNPATH_HOST_TEST_SOURCE": "$(S)/tst/glibc_runpath_host_test.c",
        "DLFCN_GLIBC_RUNPATH_SIBLING_TEST_SOURCE": "$(S)/tst/glibc_runpath_sibling_test.c",
        "DLFCN_GLIBC_TEST_SOURCE": "$(S)/tst/glibc_test.c",
        "DLFCN_GLIBC_GUEST_TEST_SOURCE": "$(S)/tst/glibc_guest_test.c",
        "DLFCN_SMOKE": "$(B)/tst/smoke",
        "DLFCN_SOLO": "$(B)/bin/solo/solo",
        "DLFCN_SYSROOT_LIB": sysroot_lib,
        "DLFCN_SYSROOT_INCLUDES": sysroot_includes,
    },
    descr="TS",
    color="green",
)

# The corpus tables are generated data: dev/generate_corpus.py ranks the
# library packages by Debian popcon votes, keeps the regression anchors
# (jemalloc's initial-exec TLS), and computes each load node's dependency
# closure from the package index. One JSON per architecture; every .so of
# a load package is loaded eagerly through SoLo, and the glibc ABI
# coverage lands in $(B)/tst/coverage.info for the coverage service.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"tst/corpus_{machine}.json")) as corpus_file:
    corpus_table = json.load(corpus_file)

corpus_dependencies = {}
corpus_load_packages = []
for corpus_name, corpus_info in corpus_table["packages"].items():
    downloadPackage(
        corpus_name,
        corpus_table["snapshot"] + corpus_info["filename"],
        corpus_info["filename"].rsplit("/", 1)[1],
        corpus_info["sha256"],
    )
    if corpus_info["load"]:
        corpus_load_packages.append(corpus_name)
        corpus_dependencies[corpus_name] = corpus_info["dependencies"]

# The ABI probe reads the Arch glibc package layout; on aarch64 the smoke
# sysroot is Debian, so the probe stays an x86-64 tool for now.
if machine == "x86_64":
    # The glibc-vs-musl ABI table: reruns only when the pinned glibc, the vendored
    # musl, or the suspect list in the probe changes.
    abi_diff = command(
        name="abi_diff",
        inputs=[
            "$(S)/dev/abi_diff.py",
            "$(S)/dev/abi_probe.c",
            downloadOutputs["glibc"],
            downloadOutputs["linux-api-headers"],
        ],
        outputs=["$(B)/tst/abi-diff.txt"],
        deps=[
            musl_alltypes,
            musl_syscall,
            downloadTargets["glibc"],
            downloadTargets["linux-api-headers"],
        ],
        cmd=[
            "python3",
            "$(S)/dev/abi_diff.py",
            "$(B)/tst/abi-diff.txt",
            cc,
            "$(S)/dev/abi_probe.c",
            downloadOutputs["glibc"],
            downloadOutputs["linux-api-headers"],
            f"{musl_root}/arch/{machine}:{musl_root}/arch/generic:$(B)/bin/vulkan/musl/include:{musl_root}/include",
        ],
        descr="TS",
        color="green",
    )

corpus_load = vendoredTest("corpus_load", "$(S)/tst/corpus_load.cpp")

corpus_results = []
corpus_result_targets = []

for name in corpus_load_packages:
    dependencies = corpus_dependencies.get(name, [])
    result = f"$(B)/tst/corpus/{name}.json"

    corpus_results.append(result)
    corpus_result_targets.append(command(
        name=f"corpus_{name}",
        inputs=[
            "$(S)/tst/corpus.py",
            downloadOutputs[name],
            *[downloadOutputs[dependency] for dependency in dependencies],
        ],
        outputs=[result],
        deps=[
            corpus_load,
            downloadTargets[name],
            *[downloadTargets[dependency] for dependency in dependencies],
        ],
        cmd=[
            "python3",
            "$(S)/tst/corpus.py",
            "load",
            result,
            "$(B)/tst/corpus_load",
            downloadOutputs[name],
            *[downloadOutputs[dependency] for dependency in dependencies],
        ],
        descr="TS",
        color="green",
    ))

corpus = command(
    name="corpus",
    inputs=[
        "$(S)/tst/corpus.py",
        f"$(S)/lib/glibc_symbols_{machine}.json",
        *corpus_results,
    ],
    outputs=["$(B)/tst/corpus-report.txt", "$(B)/tst/coverage.info"],
    deps=corpus_result_targets,
    cmd=[
        "python3",
        "$(S)/tst/corpus.py",
        "report",
        "$(B)/tst/corpus-report.txt",
        "$(B)/tst/coverage.info",
        f"$(S)/lib/glibc_symbols_{machine}.json",
        *corpus_results,
    ],
    descr="TS",
    color="green",
)

install(dlfcn)
group("test", pthread_test, arch_smoke)
# Everything the tests download, for warming a package mirror in one pass.
group("fetch", *downloadTargets.values())
