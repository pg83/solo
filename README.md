# SoLo — a `.so` loader for static Linux binaries

[![CI](https://github.com/pg83/solo/actions/workflows/ci.yml/badge.svg)](https://github.com/pg83/solo/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pg83/solo/graph/badge.svg)](https://app.codecov.io/gh/pg83/solo)

**Ship one musl-linked executable. At runtime, load the user's existing
glibc-linked GPU driver. No container, no AppImage, and no second libc in the
process.**

Static binaries are a wonderfully boring way to deploy software on Linux: one
file, no dependencies, nothing to break. We build ours with
[IX](https://github.com/pg83/ix), a source-first build system for producing
fully static Linux binaries. The boredom ends the moment the application needs
the GPU: Vulkan and OpenGL drivers are supplied by the host as shared objects,
usually built against glibc, and a fully static musl binary cannot normally
`dlopen()` them.

SoLo crosses that boundary. It provides a `dlfcn`-style source API backed by
its own ELF loader (x86-64 and aarch64) and a glibc ABI bridge implemented on
top of musl.
The result is still one ordinary static executable, but it can use the graphics
driver already installed on the machine.

The repository includes an end-to-end Vulkan proof: a fully static executable
loads the host's unmodified Vulkan driver, runs a compute shader, and writes
the result to a PNG. Tested on AMD radv, radeonsi, Intel, and NVIDIA GPUs under
Linux, on Apple M1 under Asahi Linux, on Android under Termux, and on WSL with
Mesa's dzn driver over Direct3D 12.

**The host keeps the hardware-specific code. You ship everything else.**

And not on a demo's word alone: on every commit, CI loads the shared
libraries of the 1,000 most-installed Debian packages — over 2,100 host
objects — through SoLo, on both x86-64 and aarch64.

## See it work

Grab the prebuilt binary — no clone, no toolchain, any Linux with a Vulkan
driver installed (`mesa-vulkan-drivers` is enough):

```sh
curl -LO https://github.com/pg83/solo/releases/latest/download/vulkan-x86_64
chmod +x vulkan-x86_64
./vulkan-x86_64 hello.png
```

`vulkan-aarch64` is the same demo for arm64 machines. The command discovers
the distro-installed Vulkan ICD in the usual way and produces a 512×512 RGBA
image. This is how we build the
[Shitty release binaries](https://github.com/pg83/shitty/releases)—a blazingly
fast terminal emulator, BTW! To force a particular driver:

```sh
./vulkan-x86_64 --driver /usr/share/vulkan/icd.d/radeon_icd.x86_64.json radeon.png
./vulkan-x86_64 --driver /usr/share/vulkan/icd.d/lvp_icd.json lavapipe.png
```

ICD manifest names vary slightly between distributions. Passing no `--driver`
lets the embedded Khronos loader perform its normal discovery.

You can verify that the executable itself is not dynamically linked:

```sh
readelf -lW ./vulkan-x86_64 | grep INTERP    # no output
readelf -dW ./vulkan-x86_64                  # "There is no dynamic section"
```

Or build the same demo from source, with Python 3 and a C/C++ compiler in
`PATH`:

```sh
git clone https://github.com/pg83/solo.git
cd solo
./build vulkan
./vulkan hello.png
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
│                                                                 │
│  application → embedded Vulkan loader → SoLo dlopen/dlsym       │
│                                           ├─ x86-64 ELF mapper  │
│                                           └─ glibc ABI → musl   │
│                                           │                     │
└───────────────────────────────────────────┬─────────────────────┘
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

Because musl sizes its synchronization objects to the glibc ABI of each
architecture, the bridge does not shadow them: a `pthread_mutex_t` a driver
creates is used in place. A lock is therefore one lock for both the loaded DSO
and the static executable that may share it, and glibc's static recursive and
error-check initializers are adopted on first use.

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

In the general case, only SoLo lets a static application tell the dynamic
loader: "for this system DSO's `libwayland` dependency, use the symbols already
linked into my executable." This lets the application embed the newest
`libwayland` instead of targeting the oldest version available on every
supported system.

And the boundary between the two worlds is not a thin dlsym shim — it carries
the parts that make foreign code actually behave:

- **C++ exceptions cross it in both directions.** A throw in the static world
  unwinds through glibc-compiled frames into a glibc `catch`, and the other
  way around, destructors running on both sides: the guests' `_Unwind_*`
  imports are bound to the one unwinder in the executable, so there is a
  single exception machinery in the process instead of two fighting ones.
- **All four TLS models, without wrappers or code patching.** General- and
  local-dynamic through `__tls_get_addr`, TLSDESC through its custom-ABI
  resolver, and initial-exec — whose GOT slots are plain
  thread-pointer-relative offsets no loader can intercept — served from a
  surplus arena that rides in the executable's own static TLS, so one
  process-wide offset is valid in every thread and unmodified musl does the
  per-thread layout.
- **`ld.so`'s binding semantics, not an approximation.** Global-scope
  interposition, `RTLD_DEEPBIND`, `DT_SYMBOLIC`, symbol versioning with the
  unversioned-provider compatibility rule, lazy PLT binding with the
  argument registers preserved through the resolver, GNU and SysV hash
  lookups, ifunc resolvers handed their hwcaps, `/etc/ld.so.cache`.
- **Cross-world introspection.** `backtrace()` walks static and glibc frames
  alike and names both through one `dladdr`; `dl_iterate_phdr`, `dladdr1`,
  and the `link_map` facade let unwinders and profilers see every image; the
  file-backed mappings keep real paths in `/proc/self/maps` for debuggers.
- **The stateful corners of glibc, for real.** `getcontext` /
  `makecontext` / `swapcontext` in assembly against glibc's `mcontext`
  layouts on both architectures, the pre-2.34 pthread ABIs, GNU obstacks,
  the fortified `_chk` family, and the inline-stdio ABI — musl's `FILE` is
  deliberately laid out so glibc's inlined `putc_unlocked` compiles against
  it — down to `_IO_2_1_stdout_` resolving to musl's own stream.

Every one of these is exercised by a conformance battery compiled against
real glibc headers at `-O2`, and by loading every shared object of the
thousand most-installed Debian library packages in CI, on x86-64 and
aarch64.

- [android2gnulinux](https://github.com/Cloudef/android2gnulinux) and its
  continuation [bionic_translation](https://gitlab.com/android_translation_layer/bionic_translation)
  are the closest relatives: a modified AOSP linker maps bionic-linked DSOs on
  a glibc or musl host, with their libc, pthread, and libdl imports shimmed
  onto the host's runtime — one libc in the process, SoLo's philosophy in the
  Android-to-desktop direction. Their host stays an ordinary dynamic
  executable next to the platform's `ld.so`, and bionic's unversioned imports
  sidestep glibc's versioned resolution; SoLo starts from a fully static
  binary with no system loader at all, and covers the same bionic ground with
  its Termux personality.
- [gcompat](https://github.com/Stantheman/gcompat) is a distribution-level
  glibc API shim for running prebuilt glibc binaries on musl. Its loader stub
  re-executes the program through musl's dynamic linker with `libgcompat.so`
  preloaded; using it from a musl program requires linking that shared library
  or adding it to the loaded DSO's `DT_NEEDED`. It does not give a fully static
  musl process a dynamic loader. SoLo's self-contained model is stronger: the
  executable embeds both the ELF loader and ABI bridge, loads unchanged host
  DSOs without a system compatibility package, preserves the versions of their
  glibc imports, and lets unused unsupported functions remain behind
  symbol-specific, fail-loud stubs instead of blocking the entire DSO.
- [Detour](https://github.com/graphitemaster/detour) bootstraps the system's
  `ld-linux` and allows multiple C runtimes to coexist. SoLo takes the opposite
  route: it maps the required DSOs itself and translates their glibc imports
  onto musl, so a second libc and its TLS state never enter the process.
- [Cosmopolitan Libc's `cosmo_dlopen()`](https://github.com/jart/cosmopolitan/blob/master/libc/dlopen/dlopen.c)
  follows the same split-runtime scheme as Detour, with all of its advantages
  and drawbacks: it bootstraps the host's ELF interpreter and libc, then
  delegates loading the target DSO to the host's `dlopen()`.
- ClickHouse's experimental [userspace dynamic loader](https://github.com/ClickHouse/ClickHouse/pull/110125)
  currently maps ELF objects itself, but stops short of loading glibc. Its
  proposed path to real-world system libraries such as CUDA is Detour-like:
  bootstrap the system's `ld.so`, keep a second libc runtime, and swap the
  musl/glibc thread pointer at every boundary. SoLo instead implements the
  glibc ABI over the host's musl runtime and can satisfy DSO dependencies from
  providers already linked into the static executable.
- [graphics.gd's `musl` + `dlopen` experiment](https://github.com/quaadgras/graphics.gd/discussions/242)
  follows the same split-runtime model as Detour: an embedded helper brings in
  the host's glibc loader, and assembly trampolines switch between musl and
  glibc TLS around foreign calls. This leaves two independent TLS worlds: every
  boundary crossing needs a trampoline, and a callback implemented in musl
  cannot be passed safely to glibc code because glibc invokes it while its own
  TLS is active. SoLo keeps a single musl TLS world instead.
- Flatpak, AppImage, and containers solve the problem by hiding a small Linux
  distribution inside or around your program. This works in roughly the same
  way that moving house solves a missing power adapter. The result is a huge
  blob full of duplicated libraries, mounts, namespaces, extraction tricks,
  and runtime indirection—all of which make profiling, debugging, and basic
  introspection worse. Shipping a distro because you need one system `.so` is
  not portability. SoLo ships one normal, inspectable executable and borrows
  the only component that genuinely belongs to the host: its hardware driver.

## Scope

- Linux only, on x86-64 and aarch64. The loader, the TLSDESC and lazy-PLT
  resolvers, and the initial-exec arena cover both; the glibc symbol
  inventories are generated per architecture, so `printf@GLIBC_2.2.5` on one
  is `printf@GLIBC_2.17` on the other without a single translation rule in
  the code;
- focused on real Mesa/Vulkan ICD dependency closures, and driven by the top
  1000 Debian library packages by popcon votes: the 885 of them that ship
  glibc-linked shared objects — about 2100 objects — all load through SoLo
  in CI on both architectures. Loading is the floor, not the claim: calls
  into the symbols the bridge still stubs abort loudly, and
  [dev/abi-demand.txt](dev/abi-demand.txt) is the remaining work, ranked by
  how many installations demand each symbol;
- a load-once runtime (`dlclose` succeeds but does not unload an image);
- supporting all four TLS models. Initial-exec variables are placed in a
  16 KiB surplus arena that rides in the executable's own static TLS, so one
  process-wide offset is valid in every thread without patching musl. The one
  restriction: threads created *before* a `dlopen` see zero-initialized TLS
  for the modules it loaded, so load initial-exec libraries before spawning
  the threads that use them. An initial-exec module that does not fit the
  arena fails to load with an error naming the image and the byte counts;
- explicit about missing ABI coverage: an unimplemented glibc call aborts and
  names itself.

The goal is to turn the hard wall between “fully static” and “uses the system
GPU” into a finite, testable compatibility layer. The Vulkan PNG is the first
proof that the wall has a door.
