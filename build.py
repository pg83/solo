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

linker_flags = []

if shutil.which("ld") is None and (lld := shutil.which("ld.lld")):
    linker_flags.append(f"-fuse-ld={lld}")

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
            f"$(S)/lib/{kind}_symbols.json",
        ],
        outputs=[output],
        cmd=[
            "python3",
            "$(S)/dev/generate_symbol_headers.py",
            kind,
            f"$(S)/lib/{kind}_symbols.json",
            output,
        ],
    )


musl_symbols_header = symbolHeader("musl")
glibc_symbols_header = symbolHeader("glibc")
symbol_headers = [musl_symbols_header, glibc_symbols_header]

dlfcn_srcs = [
    "$(S)/lib/dlfcn.cpp",
    "$(S)/lib/elf_loader.cpp",
    "$(S)/lib/glibc_shim.cpp",
    "$(S)/lib/glibc_stubs.cpp",
    "$(S)/lib/hash.cpp",
    "$(S)/lib/iface_handle.cpp",
    "$(S)/lib/musl_provider.cpp",
    "$(S)/lib/musl_symbols.cpp",
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
        f"{root}/src/ldso/x86_64/dlsym.s",
    }
    generic = [
        *build.glob(f"{root}/src/*/*.c"),
        *build.glob(f"{root}/src/malloc/mallocng/*.c"),
    ]
    architecture = [
        *build.glob(f"{root}/src/*/x86_64/*.[csS]"),
        *build.glob(f"{root}/src/malloc/mallocng/x86_64/*.[csS]"),
    ]
    replacements = {
        source.replace("/x86_64/", "/").rsplit(".", 1)[0]
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
    f"{musl_root}/arch/x86_64",
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
    f"{musl_root}/arch/x86_64",
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
        f"{musl_root}/arch/x86_64/bits/alltypes.h.in",
        f"{musl_root}/include/alltypes.h.in",
    ],
    outputs=["$(B)/bin/vulkan/musl/include/bits/alltypes.h"],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "alltypes",
        "$(B)/bin/vulkan/musl/include/bits/alltypes.h",
        f"{musl_root}/arch/x86_64/bits/alltypes.h.in",
        f"{musl_root}/include/alltypes.h.in",
    ],
)

musl_syscall = command(
    inputs=[
        f"{vulkan_root}/generate.py",
        f"{musl_root}/arch/x86_64/bits/syscall.h.in",
    ],
    outputs=["$(B)/bin/vulkan/musl/include/bits/syscall.h"],
    cmd=[
        "python3",
        f"{vulkan_root}/generate.py",
        "syscall",
        "$(B)/bin/vulkan/musl/include/bits/syscall.h",
        f"{musl_root}/arch/x86_64/bits/syscall.h.in",
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
vulkan_crti = muslCrt("crti", f"{musl_root}/crt/x86_64/crti.s")
vulkan_crtn = muslCrt("crtn", f"{musl_root}/crt/x86_64/crtn.s")

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
        "/usr/share/vulkan/icd.d/lvp_icd.x86_64.json",
        "$(B)/tst/lavapipe.png",
    ],
    descr="TS",
    color="green",
)

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
]

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
    inputs=["$(S)/tst/glibc_test.c", "$(S)/tst/glibc_exception_test.cpp", "$(S)/tst/run_smoke.py", *archives],
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
        "DLFCN_GLIBC_TEST_SOURCE": "$(S)/tst/glibc_test.c",
        "DLFCN_SMOKE": "$(B)/tst/smoke",
    },
    descr="TS",
    color="green",
)

# A corpus of real glibc-linked libraries with a dependency closure that stays
# inside the corpus (plus zlib from the smoke set). Every .so is loaded
# eagerly through SoLo, and the resulting glibc ABI coverage lands in
# $(B)/tst/coverage.info for the coverage service.
corpus_packages = [
    (
        "sqlite",
        "https://archive.archlinux.org/packages/s/sqlite/"
        "sqlite-3.53.4-1-x86_64.pkg.tar.zst",
        "sqlite-3.53.4-1-x86_64.pkg.tar.zst",
        "910e7e59acc3a51c7e3468bb45c7ca20d5e987eaf2c26e4e8ad9f0624bef76d2",
    ),
    (
        "openssl",
        "https://archive.archlinux.org/packages/o/openssl/"
        "openssl-3.6.3-1-x86_64.pkg.tar.zst",
        "openssl-3.6.3-1-x86_64.pkg.tar.zst",
        "85fdbdd57b6773a9b94d4d54c39deecd808aac6bc48d6d42c36ce712283665b3",
    ),
    (
        "expat",
        "https://archive.archlinux.org/packages/e/expat/"
        "expat-2.8.3-1-x86_64.pkg.tar.zst",
        "expat-2.8.3-1-x86_64.pkg.tar.zst",
        "04785503de1fb932eec7c8a7d50a815c4706df293bf7acf92953be02882c6cad",
    ),
    (
        "libffi",
        "https://archive.archlinux.org/packages/l/libffi/"
        "libffi-3.8.0-1-x86_64.pkg.tar.zst",
        "libffi-3.8.0-1-x86_64.pkg.tar.zst",
        "5d21227f2a1d10db60d0cf5bb02b36a1801ae61dc7dae8c3bc1afa548afd8601",
    ),
    (
        "pcre2",
        "https://archive.archlinux.org/packages/p/pcre2/"
        "pcre2-10.47-1-x86_64.pkg.tar.zst",
        "pcre2-10.47-1-x86_64.pkg.tar.zst",
        "54e0d8c998d2748f47fead1926b04357719bdd00fa1cea84901c3af501aab002",
    ),
    (
        "zstd",
        "https://archive.archlinux.org/packages/z/zstd/"
        "zstd-1.5.7-3-x86_64.pkg.tar.zst",
        "zstd-1.5.7-3-x86_64.pkg.tar.zst",
        "d4cf0049137124c8a025eedfad267a3e8a02310c9efb9d1ae4a61aa1d02789fc",
    ),
    (
        "xz",
        "https://archive.archlinux.org/packages/x/xz/"
        "xz-5.8.3-1-x86_64.pkg.tar.zst",
        "xz-5.8.3-1-x86_64.pkg.tar.zst",
        "03b9eefeb02c27c4f30fce4481cb5bd2922c0391f628665911c156970285d5d9",
    ),
    (
        "bzip2",
        "https://archive.archlinux.org/packages/b/bzip2/"
        "bzip2-1.0.8-6-x86_64.pkg.tar.zst",
        "bzip2-1.0.8-6-x86_64.pkg.tar.zst",
        "8779003d659c441b952095c19907603a738c1366f25cc51be3fd139fa4e95748",
    ),
    (
        "libpng",
        "https://archive.archlinux.org/packages/l/libpng/"
        "libpng-1.6.58-2-x86_64.pkg.tar.zst",
        "libpng-1.6.58-2-x86_64.pkg.tar.zst",
        "54d7a4647f7289e2c5dc44f87e325d3c84af82b6277fcc292f9a80cdf31e2a69",
    ),
    (
        "brotli",
        "https://archive.archlinux.org/packages/b/brotli/"
        "brotli-1.2.0-1-x86_64.pkg.tar.zst",
        "brotli-1.2.0-1-x86_64.pkg.tar.zst",
        "4a0c95d5967476d0efdaf76d344b61e3eee02cd7920a315e457f3fd96311b7ec",
    ),
    (
        "util-linux-libs",
        "https://archive.archlinux.org/packages/u/util-linux-libs/"
        "util-linux-libs-2.42.2-1-x86_64.pkg.tar.zst",
        "util-linux-libs-2.42.2-1-x86_64.pkg.tar.zst",
        "50e5541bafc8e7013d1cfe7fe90cba2d5e96ac05acf3e8d1540f21daf24fb9c9",
    ),
    (
        "systemd-libs",
        "https://archive.archlinux.org/packages/s/systemd-libs/"
        "systemd-libs-261.2-1-x86_64.pkg.tar.zst",
        "systemd-libs-261.2-1-x86_64.pkg.tar.zst",
        "c12d5a2c4bb7cc0088af3f6addddac3219277a14b4aefb135b508d6d9ea15de9",
    ),
    (
        "libcap",
        "https://archive.archlinux.org/packages/l/libcap/"
        "libcap-2.78-1-x86_64.pkg.tar.zst",
        "libcap-2.78-1-x86_64.pkg.tar.zst",
        "3e984fe1d323b1c5a5fc60fef005776a4882fbca913d6fe3c41ad11128929ed1",
    ),
    (
        "lz4",
        "https://archive.archlinux.org/packages/l/lz4/"
        "lz4-1:1.10.0-2-x86_64.pkg.tar.zst",
        "lz4-1:1.10.0-2-x86_64.pkg.tar.zst",
        "c6200c776440678fe8c26adae6c104194b425d9393a9e3fc09f934363f0c39a6",
    ),
    (
        "ncurses",
        "https://archive.archlinux.org/packages/n/ncurses/"
        "ncurses-6.6-2-x86_64.pkg.tar.zst",
        "ncurses-6.6-2-x86_64.pkg.tar.zst",
        "9b80390fd681121443a45a51b74e2e2ade245ce22af8769915d63165b727e27c",
    ),
    (
        "readline",
        "https://archive.archlinux.org/packages/r/readline/"
        "readline-8.3.003-1-x86_64.pkg.tar.zst",
        "readline-8.3.003-1-x86_64.pkg.tar.zst",
        "a4e861378069dcb15c6fbd52a1f5d9ed01b4bce5fb208268c7c182341f5f3960",
    ),
    (
        "gmp",
        "https://archive.archlinux.org/packages/g/gmp/"
        "gmp-6.3.0-3-x86_64.pkg.tar.zst",
        "gmp-6.3.0-3-x86_64.pkg.tar.zst",
        "2969061e117d2a8c19d89427b0b88e1c956a6269bc0602087d41aecd15097064",
    ),
    (
        "nettle",
        "https://archive.archlinux.org/packages/n/nettle/"
        "nettle-4.0-1-x86_64.pkg.tar.zst",
        "nettle-4.0-1-x86_64.pkg.tar.zst",
        "679138a8405ca383aba7836d54fdc282db9394b7dc23c097b8965f70119adf13",
    ),
    (
        "libgpg-error",
        "https://archive.archlinux.org/packages/l/libgpg-error/"
        "libgpg-error-1.61-1-x86_64.pkg.tar.zst",
        "libgpg-error-1.61-1-x86_64.pkg.tar.zst",
        "7d5a5b39f588b275558f5e13bd792bff84cf89abb6d48e3e494d6c30e8ea9ca4",
    ),
    (
        "libgcrypt",
        "https://archive.archlinux.org/packages/l/libgcrypt/"
        "libgcrypt-1.12.2-1-x86_64.pkg.tar.zst",
        "libgcrypt-1.12.2-1-x86_64.pkg.tar.zst",
        "27429de23607abb32994f589574d6e680ca3ddf0fdebae82b23fddb4f66ec64c",
    ),
    (
        "libsodium",
        "https://archive.archlinux.org/packages/l/libsodium/"
        "libsodium-1.0.22-1-x86_64.pkg.tar.zst",
        "libsodium-1.0.22-1-x86_64.pkg.tar.zst",
        "fc0440c108fff0341f3cb7b4ee38f5a9406b45d9315205ce999e1b147b52f972",
    ),
    (
        "json-c",
        "https://archive.archlinux.org/packages/j/json-c/"
        "json-c-0.19-1-x86_64.pkg.tar.zst",
        "json-c-0.19-1-x86_64.pkg.tar.zst",
        "a2ebb9395bfc18a29abd21b6dd756519114e4e6241d6321588ada285ded4d63f",
    ),
    (
        "libjpeg-turbo",
        "https://archive.archlinux.org/packages/l/libjpeg-turbo/"
        "libjpeg-turbo-3.2.0-2-x86_64.pkg.tar.zst",
        "libjpeg-turbo-3.2.0-2-x86_64.pkg.tar.zst",
        "14e743e58bbab35665d3e59ea71bd411f81a01d995e0101442f5f4c82c9de0ab",
    ),
    (
        "libdeflate",
        "https://archive.archlinux.org/packages/l/libdeflate/"
        "libdeflate-1.25-1-x86_64.pkg.tar.zst",
        "libdeflate-1.25-1-x86_64.pkg.tar.zst",
        "4e9b5d01558db0cddfbd2a6a48ed6baf92bbe65af4d0dd1ae390206fe76080ee",
    ),
    (
        "jbigkit",
        "https://archive.archlinux.org/packages/j/jbigkit/"
        "jbigkit-2.1-8-x86_64.pkg.tar.zst",
        "jbigkit-2.1-8-x86_64.pkg.tar.zst",
        "ca53fa884681273162aadcf99c30514a7010d5e621eb0a5ae491500ae8dc52c9",
    ),
    (
        "libwebp",
        "https://archive.archlinux.org/packages/l/libwebp/"
        "libwebp-1.6.0-2-x86_64.pkg.tar.zst",
        "libwebp-1.6.0-2-x86_64.pkg.tar.zst",
        "a80e7edd3ddd27c6fd8cd83d0bd98d46b3f0279b7ee01f5baeded0d6f26f8975",
    ),
    (
        "libtiff",
        "https://archive.archlinux.org/packages/l/libtiff/"
        "libtiff-4.7.2-1-x86_64.pkg.tar.zst",
        "libtiff-4.7.2-1-x86_64.pkg.tar.zst",
        "0627d404a16663e5c2fb11b6698daa69ae93ae8747ee279aecaf3f86bd547a61",
    ),
    (
        "libnghttp2",
        "https://archive.archlinux.org/packages/l/libnghttp2/"
        "libnghttp2-1.70.0-1-x86_64.pkg.tar.zst",
        "libnghttp2-1.70.0-1-x86_64.pkg.tar.zst",
        "332e2cb2d953dab326f97a3257594f8031ec0fce6305e2bcd5d64d9832c84778",
    ),
    (
        "libssh2",
        "https://archive.archlinux.org/packages/l/libssh2/"
        "libssh2-1.11.1-7-x86_64.pkg.tar.zst",
        "libssh2-1.11.1-7-x86_64.pkg.tar.zst",
        "462cca91bff394c2719b7e8d1951f0c0a2db979d71521ac93dba6b6b6974f6b9",
    ),
    (
        "libxml2",
        "https://archive.archlinux.org/packages/l/libxml2/"
        "libxml2-2.15.3-1-x86_64.pkg.tar.zst",
        "libxml2-2.15.3-1-x86_64.pkg.tar.zst",
        "51807c20a300bf85db48ae7f2f8967bec291439764b29279e3297dff3247ed4f",
    ),
    (
        "icu",
        "https://archive.archlinux.org/packages/i/icu/"
        "icu-78.3-1-x86_64.pkg.tar.zst",
        "icu-78.3-1-x86_64.pkg.tar.zst",
        "118fe41efa6c550f3fe67893946dcea2c6cbb5272299a6ddf4160fb17f3e4bb0",
    ),
    (
        "glib2",
        "https://archive.archlinux.org/packages/g/glib2/"
        "glib2-2.88.3-1-x86_64.pkg.tar.zst",
        "glib2-2.88.3-1-x86_64.pkg.tar.zst",
        "9569884e1f670d46e40ea0b8ca4ea2a1a29689be297fed1390bc5af9a03967d2",
    ),
]

for package in corpus_packages:
    downloadPackage(*package)

# The dependency closure of each corpus package: these packages are extracted
# next to it, so its DT_NEEDED entries resolve. One load node per package
# keeps the runs parallel and cached independently.
corpus_dependencies = {
    "glib2": ["pcre2", "libffi", "zlib", "util-linux-libs", "systemd-libs", "libgcc"],
    "gmp": ["libstdcxx", "libgcc"],
    "icu": ["libstdcxx", "libgcc"],
    "libgcrypt": ["libgpg-error"],
    "libpng": ["zlib"],
    "libssh2": ["openssl", "zlib", "zstd", "brotli"],
    "libtiff": ["libjpeg-turbo", "zlib", "xz", "zstd", "libdeflate", "jbigkit", "libwebp", "libstdcxx", "libgcc"],
    "libxml2": ["zlib", "xz", "icu", "libstdcxx", "libgcc"],
    "ncurses": ["libstdcxx", "libgcc"],
    "nettle": ["gmp"],
    "openssl": ["zlib", "zstd", "brotli"],
    "readline": ["ncurses"],
    "systemd-libs": ["libgcc"],
    "util-linux-libs": ["sqlite", "systemd-libs", "libgcc"],
}

downloadPackage(
    "linux-api-headers",
    "https://archive.archlinux.org/packages/l/linux-api-headers/"
    "linux-api-headers-7.2-1-x86_64.pkg.tar.zst",
    "linux-api-headers-7.2-1-x86_64.pkg.tar.zst",
    "d8d3483363e70b353ae31bbf8773df77780724eaeaa140faf4e4111bdb87588f",
)

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
        f"{musl_root}/arch/x86_64:{musl_root}/arch/generic:$(B)/bin/vulkan/musl/include:{musl_root}/include",
    ],
    descr="TS",
    color="green",
)

corpus_load = vendoredTest("corpus_load", "$(S)/tst/corpus_load.cpp")

corpus_results = []
corpus_result_targets = []

for name in [*[package[0] for package in corpus_packages], "zlib"]:
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
        "$(S)/lib/glibc_symbols.json",
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
        "$(S)/lib/glibc_symbols.json",
        *corpus_results,
    ],
    descr="TS",
    color="green",
)

install(dlfcn)
group("test", pthread_test, arch_smoke)
