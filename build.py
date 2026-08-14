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

dlfcn = library(
    srcs=[
        "$(S)/dlfcn.cpp",
        "$(S)/elf_loader.cpp",
        "$(S)/glibc_shim.cpp",
        "$(S)/glibc_stubs.cpp",
        "$(S)/hash.cpp",
        "$(S)/tlsdesc.S",
    ],
    cppflags=["-DCOMPILE_DLOPEN"],
    output="$(B)/libdlfcn.a",
)

smoke = program(
    name="smoke",
    srcs=[
        "$(S)/tst/host_symbols.cpp",
        "$(S)/tst/smoke.cpp",
    ],
    deps=[dlfcn],
    ldflags=["-static"],
    output="$(B)/tst/smoke",
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
    inputs=["$(S)/tst/run_smoke.py", *archives],
    outputs=["$(B)/tst/arch-smoke.log"],
    deps=[smoke, *downloads],
    cmd=[
        "python3",
        "$(S)/tst/run_smoke.py",
        "$(B)/tst/arch-smoke.log",
        *archives,
    ],
    env={"DLFCN_SMOKE": "$(B)/tst/smoke"},
    descr="TS",
    color="green",
)

install(dlfcn)
group("test", arch_smoke)
