import os
import shutil
import sys

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
glibc_test_cc = os.environ.get("GLIBC_TEST_CC", cc)
glibc_test_cxx = os.environ.get("GLIBC_TEST_CXX", os.environ.get("CXX", "c++"))

linker_flags = []

if shutil.which("ld") is None and (lld := shutil.which("ld.lld")):
    linker_flags.append(f"-fuse-ld={lld}")

vulkanBuild = any(argument in ("vulkan", "vulkan_test") for argument in sys.argv[1:])


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
    "$(S)/lib/musl_provider.cpp",
    "$(S)/lib/musl_symbols.cpp",
    "$(S)/lib/tlsdesc.S",
]

dlfcn = library(
    srcs=dlfcn_srcs,
    deps=symbol_headers,
    includes=["$(B)/lib"],
    cppflags=["-DCOMPILE_DLOPEN"],
    public_cppflags=["-I$(S)/lib"],
    output="$(B)/libdlfcn.a",
)

smoke = program(
    name="smoke",
    srcs=[
        "$(S)/tst/smoke.cpp",
    ],
    deps=[dlfcn],
    ldflags=["-static"],
    output="$(B)/tst/smoke",
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

if vulkanBuild:
    build.includes += [
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
    includes=musl_internal_includes,
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
    includes=["$(B)/lib"],
    cflags=c_runtime_flags,
    cxxflags=[
        *cxx_runtime_flags,
        "-Wno-bitwise-op-parentheses",
        "-Wno-shift-op-parentheses",
    ],
    cppflags=["-DCOMPILE_DLOPEN"],
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
    cflags=c_runtime_flags,
    cxxflags=cxx_runtime_flags,
    output="$(B)/bin/vulkan/lib/libvulkan_app.a",
)


def muslCrt(name, source):
    return library(
        name=f"vulkan_{name}",
        srcs=[source],
        deps=runtime_generated,
        includes=musl_internal_includes,
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

downloads = []
archives = []

for name, url, filename, sha256 in arch_packages:
    output = f"$(B)/tst/packages/{filename}"
    downloads.append(command(
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
    ))
    archives.append(output)

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

install(dlfcn)
group("test", arch_smoke)
