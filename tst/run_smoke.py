#!/usr/bin/env python3

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


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
