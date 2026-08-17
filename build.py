import os
import shutil

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
    "$(S)/lib/dlfcn.cpp",
    "$(S)/lib/elf_loader.cpp",
    "$(S)/lib/fts.cpp",
    "$(S)/lib/glibc_shim.cpp",
    "$(S)/lib/glibc_stubs.cpp",
    "$(S)/lib/hash.cpp",
    "$(S)/lib/iface_handle.cpp",
    "$(S)/lib/musl_provider.cpp",
    "$(S)/lib/musl_symbols.cpp",
    "$(S)/lib/pltresolve.S",
    "$(S)/lib/thread_tls.cpp",
    "$(S)/lib/tlsdesc.S",
]

dlfcn = library(
    srcs=dlfcn_srcs,
    deps=symbol_headers,
    includes=["$(B)/lib"],
    cppflags=["-DCOMPILE_DLOPEN", "-D_GNU_SOURCE"],
    public_cppflags=["-I$(S)/lib"],
    output="$(B)/libdlfcn.a",
)


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
target_flags = [
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-stack-protector",
    "-fno-omit-frame-pointer",
]
c_runtime_flags = [
    *target_flags,
    "-nostdinc",
]
cxx_runtime_flags = [
    "-std=c++23",
    "-nostdinc++",
]

musl = library(
    name="vulkan_musl",
    srcs=muslSources(),
    deps=runtime_generated,
    includes=[*musl_internal_includes, *vendored_includes],
    cflags=[
        *c_runtime_flags,
        "-std=c99",
        "-ffreestanding",
        "-w",
    ],
    cppflags=["-D_XOPEN_SOURCE=700"],
    output="$(B)/bin/vulkan/lib/libc.a",
)

compiler_rt_sources = [
    source for source in build.glob(f"{compiler_rt_root}/*.c")
    if not source.rsplit("/", 1)[1].startswith(("atomic", "crtbegin", "crtend"))
]
compiler_rt = library(
    name="vulkan_compiler_rt",
    srcs=compiler_rt_sources,
    deps=runtime_generated,
    includes=vendored_includes,
    cflags=[*c_runtime_flags, "-ffreestanding", "-w"],
    output="$(B)/bin/vulkan/lib/libcompiler_rt.a",
)

libunwind = library(
    name="vulkan_libunwind",
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
    cflags=[*c_runtime_flags, "-fexceptions", "-w"],
    cxxflags=[*cxx_runtime_flags, "-fno-rtti"],
    cppflags=[
        "-D_LIBUNWIND_IS_NATIVE_ONLY",
        "-D_LIBUNWIND_USE_DLADDR=0",
    ],
    output="$(B)/bin/vulkan/lib/libunwind.a",
)

libcxxabi = library(
    name="vulkan_libcxxabi",
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
    cflags=[*c_runtime_flags, "-w"],
    cxxflags=cxx_runtime_flags,
    cppflags=[
        "-D_LIBCXXABI_BUILDING_LIBRARY",
        "-D_LIBCPP_ENABLE_CXX17_REMOVED_UNEXPECTED_FUNCTIONS",
    ],
    output="$(B)/bin/vulkan/lib/libc++abi.a",
)

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
libcxx = library(
    name="vulkan_libcxx",
    srcs=libcxx_sources,
    deps=runtime_generated,
    includes=vendored_includes,
    cflags=[*c_runtime_flags, "-w"],
    cxxflags=cxx_runtime_flags,
    cppflags=[
        "-D_LIBCPP_BUILDING_LIBRARY",
        "-DLIBCXX_BUILDING_LIBCXXABI",
    ],
    output="$(B)/bin/vulkan/lib/libc++.a",
)

dlfcn_static = library(
    name="vulkan_dlfcn",
    srcs=dlfcn_srcs,
    deps=[*runtime_generated, *symbol_headers],
    includes=["$(B)/lib", *vendored_includes],
    cflags=c_runtime_flags,
    cxxflags=[
        *cxx_runtime_flags,
        "-Wno-bitwise-op-parentheses",
        "-Wno-shift-op-parentheses",
    ],
    cppflags=["-DCOMPILE_DLOPEN", "-D_GNU_SOURCE"],
    output="$(B)/bin/vulkan/lib/libdlfcn.a",
)

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


def muslCrt(name, source):
    return library(
        name=f"vulkan_{name}",
        srcs=[source],
        deps=runtime_generated,
        includes=[*musl_internal_includes, *vendored_includes],
        cflags=[
            *target_flags,
            "-w",
            "-nostdinc",
            "-DCRT",
        ],
        output=f"$(B)/bin/vulkan/crt/lib{name}.a",
    )


vulkan_crt1 = muslCrt("crt1", f"{musl_root}/crt/crt1.c")
vulkan_crti = muslCrt("crti", f"{musl_root}/crt/{machine}/crti.s")
vulkan_crtn = muslCrt("crtn", f"{musl_root}/crt/{machine}/crtn.s")

vulkan_archives = [
    vulkan_app,
    vulkan_loader,
    dlfcn_static,
    png,
    zlib,
    libcxx,
    libcxxabi,
    libunwind,
    musl,
    compiler_rt,
]
vulkan = command(
    name="vulkan",
    inputs=[
        vulkan_crt1.output,
        vulkan_crti.output,
        vulkan_crtn.output,
        *[archive.output for archive in vulkan_archives],
    ],
    outputs=["$(B)/bin/vulkan/vulkan"],
    deps=[vulkan_crt1, vulkan_crti, vulkan_crtn, *vulkan_archives],
    cmd=[
        cc,
        *linker_flags,
        "-nostdlib",
        "-static",
        "-Wl,--no-pie",
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
        dlfcn_static,
        libcxx,
        libcxxabi,
        libunwind,
        musl,
        compiler_rt,
    ]

    return command(
        name=name,
        inputs=[
            vulkan_crt1.output,
            vulkan_crti.output,
            vulkan_crtn.output,
            *[archive.output for archive in archives],
        ],
        outputs=[f"$(B)/tst/{name}"],
        deps=[vulkan_crt1, vulkan_crti, vulkan_crtn, *archives],
        cmd=[
            cc,
            *linker_flags,
            "-nostdlib",
            "-static",
            "-Wl,--no-pie",
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
            "-Wl,--no-whole-archive",
        ],
        descr="LD",
        color="light-blue",
    )


smoke = vendoredTest("smoke", "$(S)/tst/smoke.cpp")
pthread_bridge = vendoredTest("pthread_bridge", "$(S)/tst/pthread_bridge.cpp")

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
            "libc6_2.42-17_arm64.deb",
            "1426f09ab5a533b38eb6a1b462cb9df9ac2b3f82fc4d570d19d9f7789e7bc96d",
        ),
        (
            "glibc-headers",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/glibc/"
            "libc6-dev_2.42-17_arm64.deb",
            "libc6-dev_2.42-17_arm64.deb",
            "d209f637c7c0015c26794841f1af5735ea802db4461a90a5d9be1bedda53d25b",
        ),
        (
            "linux-api-headers",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/linux/"
            "linux-libc-dev_7.1.5-1_all.deb",
            "linux-libc-dev_7.1.5-1_all.deb",
            "a02af1b1e76dc4d5f8945ba6e902ab3ffbfc5a2e4f92f79ab140ccc86c9c93e1",
        ),
        (
            "vulkan-icd-loader",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/v/vulkan-loader/"
            "libvulkan1_1.4.341.0-1_arm64.deb",
            "libvulkan1_1.4.341.0-1_arm64.deb",
            "361c65aa888c61a73b6f809ec85555fd07b9f5feab8e884abc12b1dae39b3be1",
        ),
        (
            "libpciaccess",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libp/libpciaccess/"
            "libpciaccess0_0.19-2_arm64.deb",
            "libpciaccess0_0.19-2_arm64.deb",
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
    inputs=["$(S)/tst/glibc_test.c", "$(S)/tst/glibc_exception_test.cpp", "$(S)/tst/glibc_lazy_test.c", "$(S)/tst/glibc_shim_test.c", "$(S)/tst/glibc_ie_test.c", "$(S)/tst/glibc_ie_gd_test.c", "$(S)/tst/glibc_ie_ref_test.c", "$(S)/tst/glibc_big_tls_test.c", "$(S)/tst/run_smoke.py", *archives],
    outputs=["$(B)/tst/arch-smoke.log"],
    deps=[smoke, *downloads],
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
        "DLFCN_GLIBC_IE_GD_TEST_SOURCE": "$(S)/tst/glibc_ie_gd_test.c",
        "DLFCN_GLIBC_IE_REF_TEST_SOURCE": "$(S)/tst/glibc_ie_ref_test.c",
        "DLFCN_GLIBC_BIG_TLS_TEST_SOURCE": "$(S)/tst/glibc_big_tls_test.c",
        "DLFCN_GLIBC_TEST_SOURCE": "$(S)/tst/glibc_test.c",
        "DLFCN_SMOKE": "$(B)/tst/smoke",
        "DLFCN_SYSROOT_LIB": sysroot_lib,
        "DLFCN_SYSROOT_INCLUDES": sysroot_includes,
    },
    descr="TS",
    color="green",
)

# A corpus of real glibc-linked libraries, pinned inside one
# snapshot.debian.org timestamp: the snapshot archive keeps every package
# version forever, so these URLs never rot, and the same names and versions
# exist for every architecture. The dependency closure of each package stays
# inside the corpus. Every .so is loaded eagerly through SoLo, and the
# resulting glibc ABI coverage lands in $(B)/tst/coverage.info for the
# coverage service.
if machine == "x86_64":
    corpus_packages = [
        (
            "sqlite",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/sqlite3/"
            "libsqlite3-0_3.53.4-1_amd64.deb",
            "libsqlite3-0_3.53.4-1_amd64.deb",
            "40babee800d1a15ba2f6fc87075824745f2c22164955b86846a6e636d4992203",
        ),
        (
            "openssl",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/o/openssl/"
            "libssl3t64_3.6.3-1_amd64.deb",
            "libssl3t64_3.6.3-1_amd64.deb",
            "487a94fcf2120a558b60a0fcf3b6f39cdf56f125dbe15ef62ecaed9f1cb42759",
        ),
        (
            "openssl-legacy",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/o/openssl/"
            "openssl-provider-legacy_3.6.3-1_amd64.deb",
            "openssl-provider-legacy_3.6.3-1_amd64.deb",
            "bfe48a9ec5f60fd43481add5d0f730201b6882581cbd37066de89040ca00a5a7",
        ),
        (
            "expat",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/e/expat/"
            "libexpat1_2.8.2-1_amd64.deb",
            "libexpat1_2.8.2-1_amd64.deb",
            "37d24b40a745107941f823d1f22c38f197f01981f7f0783777fe0026af016463",
        ),
        (
            "libffi",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libf/libffi/"
            "libffi8_3.7.1-2_amd64.deb",
            "libffi8_3.7.1-2_amd64.deb",
            "29a8bfdbc8c66c005efc458a3a6d91c7621fa7320e05774d901ea64cd687eeb3",
        ),
        (
            "pcre2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/p/pcre2/"
            "libpcre2-8-0_10.46-1+b2_amd64.deb",
            "libpcre2-8-0_10.46-1+b2_amd64.deb",
            "a15b5dc06ffff7aab6dd7bf2e65691791162426215eff373b2cc851dc1d7848e",
        ),
        (
            "zstd",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libz/libzstd/"
            "libzstd1_1.5.7+dfsg-3+b2_amd64.deb",
            "libzstd1_1.5.7+dfsg-3+b2_amd64.deb",
            "5ce884018be1a8bd7a3beb0db95c7b18e1d49246afdfd08889bc9faa48375933",
        ),
        (
            "xz",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/x/xz-utils/"
            "liblzma5_5.8.3-1_amd64.deb",
            "liblzma5_5.8.3-1_amd64.deb",
            "4ce668e1fd6e2251068d48f72bf9f666eb29e55fade9adc933cfb0866d716be5",
        ),
        (
            "bzip2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/b/bzip2/"
            "libbz2-1.0_1.0.8-6+b2_amd64.deb",
            "libbz2-1.0_1.0.8-6+b2_amd64.deb",
            "04c7528234a6a4a8a2c2470f1470a7a616d90904fe8cdccf4c2c655540cdc61f",
        ),
        (
            "libpng",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libp/libpng1.6/"
            "libpng16-16t64_1.6.58-1_amd64.deb",
            "libpng16-16t64_1.6.58-1_amd64.deb",
            "e01786b8495d7e120333c5208e0d166f080b325f56d7213150a6e83ac912e4e8",
        ),
        (
            "brotli",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/b/brotli/"
            "libbrotli1_1.2.0-3_amd64.deb",
            "libbrotli1_1.2.0-3_amd64.deb",
            "d30e4e5a7b181a7574fd87666a124892556aefc193688e018b22b4d7400350b3",
        ),
        (
            "libmount",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libmount1_2.42.2-2_amd64.deb",
            "libmount1_2.42.2-2_amd64.deb",
            "c46d37e2456166e8fe73270c8f048f1938f417ede87ce83fb16bc31f9a164527",
        ),
        (
            "libblkid",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libblkid1_2.42.2-2_amd64.deb",
            "libblkid1_2.42.2-2_amd64.deb",
            "94cae00ff08d0cac48bc8349257830a4e354cd2a0121a639c63f3956a1cfe9a5",
        ),
        (
            "libuuid",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libuuid1_2.42.2-2_amd64.deb",
            "libuuid1_2.42.2-2_amd64.deb",
            "406c2975b7b201d94c08aa88e7ef66ba6082d6caa20dc01a49b6cc49b6354079",
        ),
        (
            "libselinux",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libselinux/"
            "libselinux1_3.11-2_amd64.deb",
            "libselinux1_3.11-2_amd64.deb",
            "07f9cadfafdebd4487b323eed5dcc7ba65bf1f639df1fcf7225869839edad539",
        ),
        (
            "systemd-libs",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libsystemd0_261.2-1_amd64.deb",
            "libsystemd0_261.2-1_amd64.deb",
            "13b8835c64c5fa97ca03107032a73c288962fa0300654a285d78624028cee6b6",
        ),
        (
            "libudev",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libudev1_261.2-1_amd64.deb",
            "libudev1_261.2-1_amd64.deb",
            "23d38d6777cac55b02b999c88f9ff17a9b14a7046b6eeb6d9901cb6bac7df15b",
        ),
        (
            "nss-systemd",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libnss-systemd_261.2-1_amd64.deb",
            "libnss-systemd_261.2-1_amd64.deb",
            "0a7e646ad3f468a2c4e76a107c45d9e99b87355f1fdf849d817e64e799a1d2da",
        ),
        (
            "nss-mymachines",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libnss-mymachines_261.2-1_amd64.deb",
            "libnss-mymachines_261.2-1_amd64.deb",
            "6860d1b474b88ad3eaced58515ae94cd01376add5204e3bd6803d28bdc3de14b",
        ),
        (
            "libcap",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libc/libcap2/"
            "libcap2_2.78-1_amd64.deb",
            "libcap2_2.78-1_amd64.deb",
            "ba722e941e4ea13c42e47b3e8fcd79529af090abf8ae530bb643a8844da74cd1",
        ),
        (
            "lz4",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/lz4/"
            "liblz4-1_1.10.0-10_amd64.deb",
            "liblz4-1_1.10.0-10_amd64.deb",
            "069d0349906af0335de6cb6a4132f0ac45c1e1db0dffffdcb5b1d291f8f6a66f",
        ),
        (
            "xxhash",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/x/xxhash/"
            "libxxhash0_0.8.3-2+b2_amd64.deb",
            "libxxhash0_0.8.3-2+b2_amd64.deb",
            "3dc2a55daf655f3c07df99b2be4cb7eea6b79089e66407f6739fe40c267907c4",
        ),
        (
            "libtinfo",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/ncurses/"
            "libtinfo6_6.6+20260608-2_amd64.deb",
            "libtinfo6_6.6+20260608-2_amd64.deb",
            "14682d1f6e35df22df0fe1eb2c09418aff0e29e2ea5a7bc0aa1bcd37192ba5a7",
        ),
        (
            "ncurses",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/ncurses/"
            "libncursesw6_6.6+20260608-2_amd64.deb",
            "libncursesw6_6.6+20260608-2_amd64.deb",
            "91dbb5e4ebe44a010703f916b4c4675aa3f54516601bbffe6612bd07e92d2071",
        ),
        (
            "readline",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/r/readline/"
            "libreadline8t64_8.3-4_amd64.deb",
            "libreadline8t64_8.3-4_amd64.deb",
            "1b65e285f312f9073dc4f0dafe44143d986bd8914e4a03af3ca59d68f238d02c",
        ),
        (
            "gmp",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gmp/"
            "libgmp10_6.3.0+dfsg-5+b2_amd64.deb",
            "libgmp10_6.3.0+dfsg-5+b2_amd64.deb",
            "032743c787f0e1e644e4dcfbdb38f01be8cb150cb9633f8be5e79aba6938f349",
        ),
        (
            "gmpxx",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gmp/"
            "libgmpxx4ldbl_6.3.0+dfsg-5+b2_amd64.deb",
            "libgmpxx4ldbl_6.3.0+dfsg-5+b2_amd64.deb",
            "c04dcc52fd657aadf385f70a0841e5df09ab81f6d0f3367ae31d6cfc8e972da7",
        ),
        (
            "nettle",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nettle/"
            "libnettle8t64_3.10.2-1+b1_amd64.deb",
            "libnettle8t64_3.10.2-1+b1_amd64.deb",
            "213f9f0119cd63efc2529401547bad5f6d2cea4cae5d05cffdef22f19aabb30e",
        ),
        (
            "hogweed",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nettle/"
            "libhogweed6t64_3.10.2-1+b1_amd64.deb",
            "libhogweed6t64_3.10.2-1+b1_amd64.deb",
            "d5872392a9d3b9b6e06f3dbd07a3f954346226d9fa2f318c4a3b5732b060fc44",
        ),
        (
            "libgpg-error",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libg/libgpg-error/"
            "libgpg-error0_1.61-3_amd64.deb",
            "libgpg-error0_1.61-3_amd64.deb",
            "4c23e2388d2eaecf74cb7143b183f37a41f87c13b1c2499009cef1504ff1d14d",
        ),
        (
            "libgcrypt",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libg/libgcrypt20/"
            "libgcrypt20_1.12.2-1_amd64.deb",
            "libgcrypt20_1.12.2-1_amd64.deb",
            "8a7fa72e7778091223400fec3ea24beb0f0d9af62a2f3f06287acb5a4fe91c60",
        ),
        (
            "libsodium",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libsodium/"
            "libsodium26_1.0.22-2_amd64.deb",
            "libsodium26_1.0.22-2_amd64.deb",
            "18d593b1aaab48f126bd3636f009fc5294f948c4960c171b7e73eab9f814f198",
        ),
        (
            "json-c",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/json-c/"
            "libjson-c5_0.19+ds-1_amd64.deb",
            "libjson-c5_0.19+ds-1_amd64.deb",
            "22a29043cacb0972466c2b978031f37a2c9fe47a3986c87bb2a6755be08844f8",
        ),
        (
            "libjpeg-turbo",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libj/libjpeg-turbo/"
            "libjpeg62-turbo_3.1.3-4_amd64.deb",
            "libjpeg62-turbo_3.1.3-4_amd64.deb",
            "402b02ea2f4aaf8922343e4c08c374cf07f26fb88323f87e1047ec475b3f12b5",
        ),
        (
            "libdeflate",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libd/libdeflate/"
            "libdeflate0_1.25-1_amd64.deb",
            "libdeflate0_1.25-1_amd64.deb",
            "2d724580f5da70168e415b776d2a8b93777a562677c13d63b438c5519d329f45",
        ),
        (
            "jbigkit",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/jbigkit/"
            "libjbig0_2.1-6.1+b3_amd64.deb",
            "libjbig0_2.1-6.1+b3_amd64.deb",
            "2ea1be21e83f9692fe50549b6129bfb3c2bc1bb3ad2d98811c61660c50ae1513",
        ),
        (
            "sharpyuv",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libw/libwebp/"
            "libsharpyuv0_1.5.0-0.1+b2_amd64.deb",
            "libsharpyuv0_1.5.0-0.1+b2_amd64.deb",
            "1cb284ea8c832fb6903ec3bd4e68a2f8d5175307753886149d9920992387f59b",
        ),
        (
            "libwebp",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libw/libwebp/"
            "libwebp7_1.5.0-0.1+b2_amd64.deb",
            "libwebp7_1.5.0-0.1+b2_amd64.deb",
            "52a7946593bfc63adbebeecc4d58fcdbebb3023e7e29f3e2aa59b063d0a80209",
        ),
        (
            "lerc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/lerc/"
            "liblerc4_4.2.0+ds-1_amd64.deb",
            "liblerc4_4.2.0+ds-1_amd64.deb",
            "6048745ecb91bfb44bc31ec24b951266923beb697f574694f006cb57c8eb0d09",
        ),
        (
            "libtiff",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/t/tiff/"
            "libtiff6_4.7.2-1_amd64.deb",
            "libtiff6_4.7.2-1_amd64.deb",
            "f621fbc15856bf88b26e7d6fe1679c0a6588e6f45f7d2f1844bc043fcf39b3df",
        ),
        (
            "libnghttp2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nghttp2/"
            "libnghttp2-14_1.69.0-1_amd64.deb",
            "libnghttp2-14_1.69.0-1_amd64.deb",
            "8747d3f60a7395f81db1d82ce4f55cc19e28c5f94da18d1804e9dcd26926888b",
        ),
        (
            "libssh2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libssh2/"
            "libssh2-1t64_1.11.1-5_amd64.deb",
            "libssh2-1t64_1.11.1-5_amd64.deb",
            "0830ea69ede584d803a26cde3684b51a2fc2d0fc450408d8253de6a308925c70",
        ),
        (
            "libxml2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libx/libxml2/"
            "libxml2-16_2.15.3+dfsg-1_amd64.deb",
            "libxml2-16_2.15.3+dfsg-1_amd64.deb",
            "b920f80146fb87f38402508ce1abda303bd3c8f4acb1f8c1b9b2f68a3c11e478",
        ),
        (
            "icu",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/i/icu/"
            "libicu78_78.3-2_amd64.deb",
            "libicu78_78.3-2_amd64.deb",
            "dc918ea6cbe7bb6feea43aac3920a86a29dcc5faf4c56d8f0948408f9076d866",
        ),
        (
            "glib2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/glib2.0/"
            "libglib2.0-0t64_2.88.3-1_amd64.deb",
            "libglib2.0-0t64_2.88.3-1_amd64.deb",
            "726d76956bace02383e86606c14f819990b06f3cbdeb340e3d3b8f7d91cb862a",
        ),
        # jemalloc carries 1976 bytes of initial-exec TLS: the regression test
        # for the surplus static TLS arena.
        (
            "jemalloc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/jemalloc/"
            "libjemalloc2_5.3.1-2_amd64.deb",
            "libjemalloc2_5.3.1-2_amd64.deb",
            "115b797f5a25d70cbe81373c9f1cce78536ed2a8a6d9dd5a061682a2340a25df",
        ),
        (
            "zlib1g",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/z/zlib/"
            "zlib1g_1.3.dfsg+really1.3.2-3_amd64.deb",
            "zlib1g_1.3.dfsg+really1.3.2-3_amd64.deb",
            "52c585b07bea72ef36df9ddd5d1937f4739d3caec057d827954baec256292651",
        ),
        (
            "libatomic",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libatomic1_16.1.0-3_amd64.deb",
            "libatomic1_16.1.0-3_amd64.deb",
            "4033832e95e8be6acae307a025420fc1a810365614c8472c591cb204a00a0853",
        ),
        (
            "libgcc-s1",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libgcc-s1_16.1.0-3_amd64.deb",
            "libgcc-s1_16.1.0-3_amd64.deb",
            "820799aced43edcc1f7fd0a32edabc8761de90ac5fd15b515b86bbd0d237c590",
        ),
        (
            "libstdcxx6",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libstdc++6_16.1.0-3_amd64.deb",
            "libstdc++6_16.1.0-3_amd64.deb",
            "f173c9a44daa0206e6c943202eb9d7c46d5817565dfbd10af16877ce0cefe585",
        ),
    ]
else:
    corpus_packages = [
        (
            "sqlite",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/sqlite3/"
            "libsqlite3-0_3.53.4-1_arm64.deb",
            "libsqlite3-0_3.53.4-1_arm64.deb",
            "d724e0c905e766a1b989cd303503128c4308bc28d7c52f2537d8cfdab8c44c21",
        ),
        (
            "openssl",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/o/openssl/"
            "libssl3t64_3.6.3-1_arm64.deb",
            "libssl3t64_3.6.3-1_arm64.deb",
            "0e58fc4beb997e87814eb10fe8056c8886379aa803f32fcc02b3ad62d09537a4",
        ),
        (
            "openssl-legacy",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/o/openssl/"
            "openssl-provider-legacy_3.6.3-1_arm64.deb",
            "openssl-provider-legacy_3.6.3-1_arm64.deb",
            "199ef2b8800964811a8d400ee366a7bb44d6c261bed682e62630462c6139ddd6",
        ),
        (
            "expat",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/e/expat/"
            "libexpat1_2.8.2-1_arm64.deb",
            "libexpat1_2.8.2-1_arm64.deb",
            "df928e3a8e4da79408d4b18e8cd80a03dffa90130d0698e50041aab5e14f9397",
        ),
        (
            "libffi",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libf/libffi/"
            "libffi8_3.7.1-2_arm64.deb",
            "libffi8_3.7.1-2_arm64.deb",
            "abf0c6ae2eb6057f90168e6f7f62cc235b3650ad141913a7f4fc9f939919cdad",
        ),
        (
            "pcre2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/p/pcre2/"
            "libpcre2-8-0_10.46-1+b2_arm64.deb",
            "libpcre2-8-0_10.46-1+b2_arm64.deb",
            "8960f598a0eaf195bf9e17ac7cf1aca7450e5d2acb3ce5a6e85f898e5a6c218f",
        ),
        (
            "zstd",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libz/libzstd/"
            "libzstd1_1.5.7+dfsg-3+b2_arm64.deb",
            "libzstd1_1.5.7+dfsg-3+b2_arm64.deb",
            "480a5f0d14feb7e95130ccf726d8b07bd69fcc01f4806c8c8df6098f75228f90",
        ),
        (
            "xz",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/x/xz-utils/"
            "liblzma5_5.8.3-1_arm64.deb",
            "liblzma5_5.8.3-1_arm64.deb",
            "3f0cd33c5f54b6cac617f4cc585d8bfce3dec2029b48a875f2c2492da9e4246a",
        ),
        (
            "bzip2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/b/bzip2/"
            "libbz2-1.0_1.0.8-6+b2_arm64.deb",
            "libbz2-1.0_1.0.8-6+b2_arm64.deb",
            "cca22caf6bcf0a547ee3d866aad175c88aab979065c179aa845b77724911c4bd",
        ),
        (
            "libpng",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libp/libpng1.6/"
            "libpng16-16t64_1.6.58-1_arm64.deb",
            "libpng16-16t64_1.6.58-1_arm64.deb",
            "3835c62ced8c5f4349439c88ada813dc9274f7a17b7cd535a22e0f1e34c9ea83",
        ),
        (
            "brotli",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/b/brotli/"
            "libbrotli1_1.2.0-3_arm64.deb",
            "libbrotli1_1.2.0-3_arm64.deb",
            "927b7c88dde186fde8bfe2015d71ccfedac9c8573aa57bd97c25eedd6552ee84",
        ),
        (
            "libmount",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libmount1_2.42.2-2_arm64.deb",
            "libmount1_2.42.2-2_arm64.deb",
            "2d3580a0d63827bd2d7083117bc165085bc486cc0cb0fb71abfa1d605c0bb2c6",
        ),
        (
            "libblkid",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libblkid1_2.42.2-2_arm64.deb",
            "libblkid1_2.42.2-2_arm64.deb",
            "91e4a395623c6a1de6cab2ba4ccdc8fb32071c808ceb347dce66eea50eed6be7",
        ),
        (
            "libuuid",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/u/util-linux/"
            "libuuid1_2.42.2-2_arm64.deb",
            "libuuid1_2.42.2-2_arm64.deb",
            "0b0268a46060a99b9dca8e2c2379dd3b24e248f97e4d561d0d74c0706c73c6b4",
        ),
        (
            "libselinux",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libselinux/"
            "libselinux1_3.11-2_arm64.deb",
            "libselinux1_3.11-2_arm64.deb",
            "61c955ed1b6dc7e99370d87a0b9ab6fd0e378766bdecf0a1e2f84e99644985bc",
        ),
        (
            "systemd-libs",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libsystemd0_261.2-1_arm64.deb",
            "libsystemd0_261.2-1_arm64.deb",
            "172ee7f0b88e456edc63726fd2628cba11376977e86c3ec0183716ff1d690d5f",
        ),
        (
            "libudev",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libudev1_261.2-1_arm64.deb",
            "libudev1_261.2-1_arm64.deb",
            "f2abc7494f29aed2b4ffddd0701f34679bdf4d94fb3ed818ed021aff422cb95f",
        ),
        (
            "nss-systemd",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libnss-systemd_261.2-1_arm64.deb",
            "libnss-systemd_261.2-1_arm64.deb",
            "464ae644039ff867c62939c174c92d8ae039d24c0af64df2364cd6bd35516854",
        ),
        (
            "nss-mymachines",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/s/systemd/"
            "libnss-mymachines_261.2-1_arm64.deb",
            "libnss-mymachines_261.2-1_arm64.deb",
            "62dfd1e2ce8450be95823b8d6c97ea871c02ca7f273856cd6174a5283d225e2c",
        ),
        (
            "libcap",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libc/libcap2/"
            "libcap2_2.78-1_arm64.deb",
            "libcap2_2.78-1_arm64.deb",
            "5ab140d5a37f3bda7bbc832600dd91937f2ba122e539668262a8115e2c4f260f",
        ),
        (
            "lz4",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/lz4/"
            "liblz4-1_1.10.0-10_arm64.deb",
            "liblz4-1_1.10.0-10_arm64.deb",
            "c088f662f310c47a92b9120f6a6e7b430ce3f0a029d3d1a554a0d3acf753b8b7",
        ),
        (
            "xxhash",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/x/xxhash/"
            "libxxhash0_0.8.3-2+b2_arm64.deb",
            "libxxhash0_0.8.3-2+b2_arm64.deb",
            "4cf0681fffcf75305814bf2276a733f2cabd9bcf5fe18430c74441723343e467",
        ),
        (
            "libtinfo",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/ncurses/"
            "libtinfo6_6.6+20260608-2_arm64.deb",
            "libtinfo6_6.6+20260608-2_arm64.deb",
            "2ba77e68fbadd96dd7aa83399ab681593d5b48e951ae63e69a7a0650dfdfaf76",
        ),
        (
            "ncurses",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/ncurses/"
            "libncursesw6_6.6+20260608-2_arm64.deb",
            "libncursesw6_6.6+20260608-2_arm64.deb",
            "a27d49cd2f7c3b02caf56b59d2c52f7bbf9d18dcbc8f96c412cf767b6b36c43e",
        ),
        (
            "readline",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/r/readline/"
            "libreadline8t64_8.3-4_arm64.deb",
            "libreadline8t64_8.3-4_arm64.deb",
            "c8f93840910ad4db3778e3b730193e8f50ad947a9f6c978fa941cb6202e934b6",
        ),
        (
            "gmp",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gmp/"
            "libgmp10_6.3.0+dfsg-5+b2_arm64.deb",
            "libgmp10_6.3.0+dfsg-5+b2_arm64.deb",
            "ceedd3ac17447facce0de2713b6f99d711fa41e7f26cb278778840054d93b6a7",
        ),
        (
            "gmpxx",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gmp/"
            "libgmpxx4ldbl_6.3.0+dfsg-5+b2_arm64.deb",
            "libgmpxx4ldbl_6.3.0+dfsg-5+b2_arm64.deb",
            "9f7feaf81e7ba0496c3e8882486040d05ce60a9585e1e72cbbd6230d7e7943ec",
        ),
        (
            "nettle",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nettle/"
            "libnettle8t64_3.10.2-1+b1_arm64.deb",
            "libnettle8t64_3.10.2-1+b1_arm64.deb",
            "b600dcf64a45508b39be31f8d415f177aa6a1c31af9b7e673063a0f4aea3875e",
        ),
        (
            "hogweed",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nettle/"
            "libhogweed6t64_3.10.2-1+b1_arm64.deb",
            "libhogweed6t64_3.10.2-1+b1_arm64.deb",
            "3b61a8059b653c98019b959419060c79e061259a8b9ec39981050dda7059c003",
        ),
        (
            "libgpg-error",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libg/libgpg-error/"
            "libgpg-error0_1.61-3_arm64.deb",
            "libgpg-error0_1.61-3_arm64.deb",
            "70826bfce8d1fd381f2e85f02c48f94055d4f804ebeca3601f9066a5bbc7d7f4",
        ),
        (
            "libgcrypt",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libg/libgcrypt20/"
            "libgcrypt20_1.12.2-1_arm64.deb",
            "libgcrypt20_1.12.2-1_arm64.deb",
            "98ddb8aa31636199777a3dfae20a6718a9a38331decfb9fa538925670b299fc9",
        ),
        (
            "libsodium",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libsodium/"
            "libsodium26_1.0.22-2_arm64.deb",
            "libsodium26_1.0.22-2_arm64.deb",
            "8eb8908fa7d4b9e20e1e6d9de47f4711d5a65adf540319219d49da456be49847",
        ),
        (
            "json-c",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/json-c/"
            "libjson-c5_0.19+ds-1_arm64.deb",
            "libjson-c5_0.19+ds-1_arm64.deb",
            "0e943d0fb043fdfec7f31040033a9c52dc7a5a3cd7276b148e59c805c9ad23a6",
        ),
        (
            "libjpeg-turbo",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libj/libjpeg-turbo/"
            "libjpeg62-turbo_3.1.3-4_arm64.deb",
            "libjpeg62-turbo_3.1.3-4_arm64.deb",
            "e494cbc89f909d3f65c8f7013bcaba92456d2e9f9f09abecebba306a1bad0e16",
        ),
        (
            "libdeflate",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libd/libdeflate/"
            "libdeflate0_1.25-1_arm64.deb",
            "libdeflate0_1.25-1_arm64.deb",
            "787599d06707e3fc7fc18b5e4cfc24c34afe6433762f0fe740bb15414f4faf15",
        ),
        (
            "jbigkit",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/jbigkit/"
            "libjbig0_2.1-6.1+b3_arm64.deb",
            "libjbig0_2.1-6.1+b3_arm64.deb",
            "646f07ee43601d65802ba26a3ca8c4cac195f4cfbcc521d70103ef865671301e",
        ),
        (
            "sharpyuv",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libw/libwebp/"
            "libsharpyuv0_1.5.0-0.1+b2_arm64.deb",
            "libsharpyuv0_1.5.0-0.1+b2_arm64.deb",
            "e60ebfc65f28a408fa16ede81e967692238ddc6c481392b194b231ddcfc26933",
        ),
        (
            "libwebp",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libw/libwebp/"
            "libwebp7_1.5.0-0.1+b2_arm64.deb",
            "libwebp7_1.5.0-0.1+b2_arm64.deb",
            "23d20e9199a11eab756fb097e2ea59009e7c525b9eec834b8c4f380f0a11447b",
        ),
        (
            "lerc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/l/lerc/"
            "liblerc4_4.2.0+ds-1_arm64.deb",
            "liblerc4_4.2.0+ds-1_arm64.deb",
            "b4a8f57ff468e35b952513d5b65e4be6abe6a68d939a507dfcbe3f8dd19e1ae8",
        ),
        (
            "libtiff",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/t/tiff/"
            "libtiff6_4.7.2-1_arm64.deb",
            "libtiff6_4.7.2-1_arm64.deb",
            "f9d9dcecd56355c783d697e73669b3e375ea9afeb0028d9813160bb3134075c2",
        ),
        (
            "libnghttp2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/n/nghttp2/"
            "libnghttp2-14_1.69.0-1_arm64.deb",
            "libnghttp2-14_1.69.0-1_arm64.deb",
            "dab33625de27f86c0f05fa8f3395602bdbe9bec3e3e1fa8f0c0d24771c5014e1",
        ),
        (
            "libssh2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libs/libssh2/"
            "libssh2-1t64_1.11.1-5_arm64.deb",
            "libssh2-1t64_1.11.1-5_arm64.deb",
            "670270f91c0033d18fad9b272fd5eb0a9f0bd5c46dca1ed28afe268002486932",
        ),
        (
            "libxml2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/libx/libxml2/"
            "libxml2-16_2.15.3+dfsg-1_arm64.deb",
            "libxml2-16_2.15.3+dfsg-1_arm64.deb",
            "9bf79dd60d331dd436af86b34a86341d14ce0d1ef2a2f7ff4e39d597fcc730d1",
        ),
        (
            "icu",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/i/icu/"
            "libicu78_78.3-2_arm64.deb",
            "libicu78_78.3-2_arm64.deb",
            "1f1ff7e0072bc7b273a9287829bcd367051d147426f483f17c92654ff3fa62f1",
        ),
        (
            "glib2",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/glib2.0/"
            "libglib2.0-0t64_2.88.3-1_arm64.deb",
            "libglib2.0-0t64_2.88.3-1_arm64.deb",
            "d4406f7b0ae4940d4d1958db99722960311293a6086ab047585a63498248ba1a",
        ),
        # jemalloc carries initial-exec TLS: the regression test for the
        # surplus static TLS arena, on this architecture too.
        (
            "jemalloc",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/j/jemalloc/"
            "libjemalloc2_5.3.1-2_arm64.deb",
            "libjemalloc2_5.3.1-2_arm64.deb",
            "298ead4fc70c62f7d3b987e216b9c382b40112b549401431f919aa71273322ac",
        ),
        (
            "zlib1g",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/z/zlib/"
            "zlib1g_1.3.dfsg+really1.3.2-3_arm64.deb",
            "zlib1g_1.3.dfsg+really1.3.2-3_arm64.deb",
            "a77a1a137da4f6e440fa638b00a60dc3d7124e9678402ea5335bc02e75bf267e",
        ),
        (
            "libatomic",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libatomic1_16.1.0-3_arm64.deb",
            "libatomic1_16.1.0-3_arm64.deb",
            "f703c38e02762f2def3ace437c6bc0b727b9b9c51af112c7bb78321c8afe6f25",
        ),
        (
            "libgcc-s1",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libgcc-s1_16.1.0-3_arm64.deb",
            "libgcc-s1_16.1.0-3_arm64.deb",
            "f5e30fd43af507b7674cac5f776b97db0a0ae5f97c6ec0103c828e15060a7f95",
        ),
        (
            "libstdcxx6",
            "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
            "pool/main/g/gcc-16/"
            "libstdc++6_16.1.0-3_arm64.deb",
            "libstdc++6_16.1.0-3_arm64.deb",
            "837c4a9d01e2aff0866264e1d90ae25775c90e5262beec9b36dc9a088eb3938f",
        ),
    ]

for package in corpus_packages:
    downloadPackage(*package)

# The dependency closure of each corpus package: these packages are extracted
# next to it, so its DT_NEEDED entries resolve. One load node per package
# keeps the runs parallel and cached independently.
corpus_dependencies = {
    "glib2": ["pcre2", "libffi", "zlib1g", "libmount", "libblkid", "libselinux", "systemd-libs", "libatomic", "libgcc-s1"],
    "gmpxx": ["gmp", "libstdcxx6", "libgcc-s1"],
    "hogweed": ["nettle", "gmp"],
    "icu": ["libstdcxx6", "libgcc-s1"],
    "jemalloc": ["libstdcxx6", "libgcc-s1"],
    "lerc": ["libstdcxx6", "libgcc-s1"],
    "libgcrypt": ["libgpg-error"],
    "libmount": ["libblkid", "libselinux", "pcre2", "systemd-libs"],
    "libpng": ["zlib1g"],
    "libselinux": ["pcre2"],
    "libssh2": ["openssl", "zstd", "zlib1g"],
    "libstdcxx6": ["libgcc-s1"],
    "libtiff": ["libjpeg-turbo", "zlib1g", "xz", "zstd", "libdeflate", "jbigkit", "libwebp", "sharpyuv", "lerc", "libstdcxx6", "libgcc-s1"],
    "libwebp": ["sharpyuv"],
    "libxml2": ["zlib1g"],
    "lz4": ["xxhash"],
    "ncurses": ["libtinfo"],
    "openssl": ["zstd", "zlib1g"],
    "openssl-legacy": ["openssl", "zstd", "zlib1g"],
    "readline": ["libtinfo"],
}

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

for name in [package[0] for package in corpus_packages]:
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
