#!/usr/bin/env python3

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def builtin_include(compiler):
    """The compiler's own header directory (stddef.h and friends)."""
    for flags in (["-print-file-name=include"], ["-print-resource-dir"]):
        result = subprocess.run(
            [*compiler, *flags], text=True, stdout=subprocess.PIPE, check=False
        )
        path = Path(result.stdout.strip())
        if flags[0] == "-print-resource-dir":
            path = path / "include"
        if result.returncode == 0 and path.is_absolute() and (path / "stddef.h").is_file():
            return path
    binary = shutil.which(compiler[0])
    if binary:
        prefix = Path(binary).resolve().parent.parent
        for candidate in [prefix / "share" / "include", *sorted(prefix.glob("lib/clang/*/include"))]:
            if (candidate / "stddef.h").is_file():
                return candidate
    raise SystemExit(f"run_smoke.py: cannot find the builtin headers of {compiler}")


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: run_smoke.py OUTPUT ARCHIVE...")

    executable = os.environ["DLFCN_SMOKE"]
    output = Path(sys.argv[1])
    archives = sys.argv[2:]

    with tempfile.TemporaryDirectory(prefix="dlfcn-test-") as temporary:
        root = Path(temporary)
        for archive in archives:
            subprocess.run(
                ["bsdtar", "-xpf", archive, "-C", str(root)],
                check=True,
            )

        library_path = root / "ld-library-path"
        library_path.mkdir()
        glibc_test = library_path / "libdlfcn-test-glibc.so"
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                str(root / "usr" / "lib" / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-glibc.so",
                os.environ["DLFCN_GLIBC_TEST_SOURCE"],
                "-o",
                str(glibc_test),
            ],
            check=True,
        )
        glibc_exception_test = library_path / "libdlfcn-test-exception.so"
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CXX"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                os.environ["DLFCN_GLIBC_EXCEPTION_TEST_SOURCE"],
                str(root / "usr" / "lib" / "libstdc++.so.6"),
                str(root / "usr" / "lib" / "libgcc_s.so.1"),
                str(root / "usr" / "lib" / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-exception.so",
                "-o",
                str(glibc_exception_test),
            ],
            check=True,
        )
        # The conformance battery compiles against the extracted glibc and
        # Linux headers, so its ABI expectations are exactly glibc's.
        compiler = shlex.split(os.environ["DLFCN_CC"])
        shim_test = library_path / "libdlfcn-test-shim.so"
        subprocess.run(
            [
                *compiler,
                # -O2 turns the glibc extern inlines on, so putc_unlocked and
                # friends compile into direct _IO_FILE field accesses.
                "-O2",
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-nostdinc",
                "-isystem",
                str(root / "usr" / "include"),
                "-isystem",
                str(builtin_include(compiler)),
                "-Wl,--no-as-needed",
                str(root / "usr" / "lib" / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-shim.so",
                os.environ["DLFCN_GLIBC_SHIM_TEST_SOURCE"],
                "-o",
                str(shim_test),
            ],
            check=True,
        )
        # Two builds of the same source: eager binding of the undefined symbol
        # must fail on one image without poisoning the lazily loadable other.
        for lazy_name in ("libdlfcn-test-lazy.so", "libdlfcn-test-lazynow.so"):
            subprocess.run(
                [
                    *shlex.split(os.environ["DLFCN_CC"]),
                    "-fPIC",
                    "-fno-stack-protector",
                    "-shared",
                    "-nostdlib",
                    "-Wl,--no-as-needed",
                    # Hardened toolchains default to -z now; the test is about
                    # lazy slots, so ask for them explicitly.
                    "-Wl,-z,lazy",
                    str(root / "usr" / "lib" / "libc.so.6"),
                    f"-Wl,-soname,{lazy_name}",
                    os.environ["DLFCN_GLIBC_LAZY_TEST_SOURCE"],
                    "-o",
                    str(library_path / lazy_name),
                ],
                check=True,
            )
        (library_path / "libdlfcn-test-pci.so").symlink_to(
            root / "usr" / "lib" / "libpciaccess.so.0"
        )
        (library_path / "libdlfcn-test-vulkan.so").symlink_to(
            root / "usr" / "lib" / "libvulkan.so.1"
        )
        (library_path / "libz.so.1").symlink_to(
            root / "usr" / "lib" / "libz.so.1"
        )
        (library_path / "libgcc_s.so.1").symlink_to(
            root / "usr" / "lib" / "libgcc_s.so.1"
        )
        (library_path / "libstdc++.so.6").symlink_to(
            root / "usr" / "lib" / "libstdc++.so.6"
        )

        environment = os.environ.copy()
        environment.pop("DL_ELF_LIBRARY_PATH", None)
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(
            (str(root / "missing"), str(library_path))
        )
        result = subprocess.run(
            [executable],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )

    print(result.stdout, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
