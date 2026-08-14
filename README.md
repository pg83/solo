# SoLo — a `.so` loader for static Linux binaries

[![CI](https://github.com/pg83/solo/actions/workflows/ci.yml/badge.svg)](https://github.com/pg83/solo/actions/workflows/ci.yml)

**Ship one musl-linked executable. At runtime, load the user's existing
glibc-linked GPU driver. No container, no AppImage, and no second libc in the
process.**

Static binaries are a wonderfully boring way to deploy software on Linux. We
build ours with [IX](https://github.com/pg83/ix), a source-first build system for
producing fully static Linux binaries. The story stays wonderfully boring—right
up until the application needs the GPU. Vulkan and OpenGL drivers are supplied
by the host as shared objects, usually built against glibc. A fully static musl
binary cannot normally `dlopen()` them.

SoLo crosses that boundary. It provides a `dlfcn`-style source API backed by
its own x86-64 ELF loader and a glibc ABI bridge implemented on top of musl.
The result is still one ordinary static executable, but it can use the graphics
driver already installed on the machine.

The repository includes an end-to-end Vulkan proof: a static executable with
no `PT_INTERP` and no `DT_NEEDED` loads an unmodified system Mesa ICD, runs a
compute shader, and writes the result to a PNG.

**The host keeps the hardware-specific code. You ship everything else.**

## See it work

On x86-64 Linux, with Python 3 and a C/C++ compiler in `PATH`:

```sh
git clone https://github.com/pg83/solo.git
cd solo
./build vulkan
./vulkan hello.png
```

The last command discovers the distro-installed Vulkan ICD in the usual way
and produces a 512×512 RGBA image. This is how we build the
[Shitty release binaries](https://github.com/pg83/shitty/releases)—a blazingly
fast terminal emulator, BTW! To force a particular driver:

```sh
./vulkan --driver /usr/share/vulkan/icd.d/radeon_icd.x86_64.json radeon.png
./vulkan --driver /usr/share/vulkan/icd.d/lvp_icd.json lavapipe.png
```

ICD manifest names vary slightly between distributions. Passing no `--driver`
lets the embedded Khronos loader perform its normal discovery.

You can verify that the executable itself is not dynamically linked:

```sh
readelf -lW ./vulkan | grep INTERP       # no output
readelf -dW ./vulkan                     # "There is no dynamic section"
```

This is not a toy call to `vkCreateInstance`. The demo:

1. enters the statically linked Khronos Vulkan loader;
2. loads the host's Vulkan ICD and its non-glibc dependencies through SoLo;
3. creates a device, storage buffer, descriptor set, and compute pipeline;
4. dispatches a checked-in SPIR-V shader;
5. maps the result and writes it through statically linked libpng.

The complete example is in [`bin/vulkan`](bin/vulkan), and the Vulkan program
itself is in [`main.cpp`](bin/vulkan/main.cpp).

## How it works

```text
┌──────────────────── fully static executable ────────────────────┐
│                                                                │
│  application → embedded Vulkan loader → SoLo dlopen/dlsym       │
│                                           ├─ x86-64 ELF mapper   │
│                                           └─ glibc ABI → musl    │
│                                           │                     │
└───────────────────────────────────────────│─────────────────────┘
                                            │ maps at runtime
                                            ▼
                              system Mesa/Vulkan ICD.so + DSOs
```

[`elf_loader.cpp`](lib/elf_loader.cpp) maps ELF segments, walks `DT_NEEDED`,
resolves versioned symbols, applies x86-64 relocations, supports ELF TLS and
TLSDESC, materializes IFUNCs, applies RELRO, and runs initializers. Dependencies
that are themselves ELF DSOs are loaded recursively.

glibc is deliberately *not* loaded. Imports such as `malloc@GLIBC_2.2.5` are
resolved by [`glibc_shim.cpp`](lib/glibc_shim.cpp) to ABI-correct adapters over
the process's existing musl runtime. Unsupported glibc functions have unique
generated stubs that fail loudly with the exact symbol and version if they are
ever called, instead of silently corrupting the process.

Before loading a DSO from disk, SoLo checks its static provider registry. This
lets an application satisfy a dependency—Wayland, for example—with functions
already linked into the executable. `LD_LIBRARY_PATH` and
`DL_ELF_LIBRARY_PATH` are honored for libraries outside the standard system
directories.

The interesting pieces are small enough to read:

- [`lib/dlfcn.cpp`](lib/dlfcn.cpp) — `dlopen`, `dlsym`, errors, and static providers
- [`lib/elf_loader.cpp`](lib/elf_loader.cpp) — ELF mapping, symbols, relocations, and TLS
- [`lib/glibc_shim.cpp`](lib/glibc_shim.cpp) — implemented glibc ABI adapters
- [`lib/glibc_stubs.cpp`](lib/glibc_stubs.cpp) — explicit fallbacks for the rest of the ABI

## Use it as a library

The default target builds the standalone archive:

```sh
./build
```

The published `./dlfcn` symlink points to the resulting `libdlfcn.a`. Include
[`lib/dlfcn.h`](lib/dlfcn.h), link the archive into a musl-static application,
and ordinary `dlopen()`/`dlsym()` calls are redirected to SoLo. The source tree
is intentionally self-contained and suitable for copying into another static
build graph.

## Reproduce the experiment

```sh
./build test          # load an Arch glibc DSO closure in the smoke test
./build vulkan_test   # build the static demo and verify a native Lavapipe PNG
```

CI performs the native build and test on Alpine/musl with GCC, Fedora with GCC,
and Ubuntu with Clang. The Vulkan test installs each distribution's own
Lavapipe package; it does not run the driver from an Arch sysroot.

Every build input for the standalone Vulkan executable is vendored under
`bin/vulkan`. [`build.py`](build.py) compiles those sources directly: upstream
CMake, Meson, configure, and Make build systems are not invoked.

<details>
<summary>Vendored versions</summary>

- musl 1.2.5 (`0784374d561435f7c787a555aeab8ede699ed298`)
- LLVM runtimes 15.0.7: libc++, libc++abi, libunwind, and compiler-rt builtins
  (`8dfdcc7b7bf66834a761bd8de445840ef68e4d1a`)
- Vulkan Headers 1.4.357 (`e3b1eec08173d6b825cd3ac88c885a63b621504a`)
- Vulkan Loader 1.4.357 (`5f157b62e333c63260d05d81bf66faa216ab0fb8`)
- zlib 1.3.2 (`da607da739fa6047df13e66a2af6b8bec7c2a498`)
- libpng 1.6.50 (`2b978915d82377df13fcbb1fb56660195ded868a`)

License files are retained beside the corresponding sources. `shader.inc` is
the checked-in SPIR-V form of `shader.comp`, so no shader compiler is required.

</details>

## How this differs from prior work

- [Cosmopolitan Libc](https://github.com/jart/cosmopolitan) and
  [Actually Portable Executables](https://justine.lol/ape.html) solve
  build-once/run-anywhere for code shipped with the program. SoLo tackles a
  different boundary: consuming Linux-only, machine-local vendor DSOs such as
  GPU drivers from a static musl process.
- [Detour](https://github.com/graphitemaster/detour) bootstraps the system's
  `ld-linux` and allows multiple C runtimes to coexist. SoLo takes the opposite
  route: it maps the required DSOs itself and translates their glibc imports
  onto musl, so a second libc and its TLS state never enter the process.
- Flatpak, AppImage, and containers solve the problem by hiding a small Linux
  distribution inside or around your program. This works in roughly the same
  way that moving house solves a missing power adapter. The result is a huge
  blob full of duplicated libraries, mounts, namespaces, extraction tricks,
  and runtime indirection—all of which make profiling, debugging, and basic
  introspection worse. Shipping a distro because you need one system `.so` is
  not portability. SoLo ships one normal, inspectable executable and borrows
  the only component that genuinely belongs to the host: its hardware driver.

## Scope

SoLo is early systems software, not a claim to implement every corner of glibc
or every ELF ever produced.

Today it is:

- Linux x86-64 only;
- focused on real Mesa/Vulkan ICD dependency closures;
- a load-once runtime (`dlclose` succeeds but does not unload an image);
- explicit about missing ABI coverage: an unimplemented glibc call aborts and
  names itself.

The goal is to turn the hard wall between “fully static” and “uses the system
GPU” into a finite, testable compatibility layer. The Vulkan PNG is the first
proof that the wall has a door.
