# solo

`solo` is a static-side `dlfcn` implementation. It loads a system x86-64 ELF
DSO into a musl process, resolves its non-glibc dependencies recursively, and
bridges the glibc ABI imports that the DSO actually uses.

## Vulkan experiment

The `vulkan` target proves the complete path with an unmodified system Vulkan
ICD. It creates a compute pipeline, renders a 512x512 RGBA image, and writes it
as a PNG. The executable itself is static: it has neither `PT_INTERP` nor
`DT_NEEDED`; Vulkan and the selected driver are loaded only at runtime.

Build on x86-64 Linux with Python 3 and a Clang/LLVM toolchain in `PATH`:

```sh
./build vulkan
```

The result is published as `./vulkan`. With normal distro-installed drivers,
the Khronos loader discovers the ICD in the standard locations:

```sh
./vulkan output.png
```

An ICD can be selected explicitly:

```sh
./vulkan --driver /usr/share/vulkan/icd.d/radeon_icd.x86_64.json output.png
./vulkan --driver /usr/share/vulkan/icd.d/lvp_icd.x86_64.json output.png
```

`LD_LIBRARY_PATH` and `DL_ELF_LIBRARY_PATH` are honored when testing a driver
unpacked outside the system directories.

All build inputs are vendored under `bin/vulkan`, and `build.py` compiles them
directly; none of their CMake, configure, Meson, or Make build systems are
invoked. The pinned inputs are:

- musl 1.2.5 (`0784374d561435f7c787a555aeab8ede699ed298`)
- LLVM runtimes 21.1.8: libc++, libc++abi, libunwind, and compiler-rt builtins
  (`2078da43e25a4623cab2d0d60decddf709aaea28`)
- Vulkan Headers 1.4.357 (`e3b1eec08173d6b825cd3ac88c885a63b621504a`)
- Vulkan Loader 1.4.357 (`5f157b62e333c63260d05d81bf66faa216ab0fb8`)
- zlib 1.3.2 (`da607da739fa6047df13e66a2af6b8bec7c2a498`)
- libpng 1.6.50 (`2b978915d82377df13fcbb1fb56660195ded868a`)

Their license files are retained beside their sources. `shader.inc` is the
checked-in SPIR-V form of `shader.comp`, so building does not require a shader
compiler. `host_symbols.cpp` is a generated static-factory table for the
ABI-compatible musl providers imported by the Arch Mesa driver closure.
