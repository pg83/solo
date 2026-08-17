#!/usr/bin/env python3

import bisect
import os
import re
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
    sysroot_lib = os.environ["DLFCN_SYSROOT_LIB"]
    sysroot_includes = os.environ["DLFCN_SYSROOT_INCLUDES"].split(":")
    output = Path(sys.argv[1])
    archives = sys.argv[2:]

    with tempfile.TemporaryDirectory(prefix="dlfcn-test-") as temporary:
        root = Path(temporary)
        for archive in archives:
            if archive.endswith(".deb"):
                data = subprocess.run(
                    ["bsdtar", "-xOf", archive, "data.tar.*"],
                    check=True,
                    stdout=subprocess.PIPE,
                ).stdout
                subprocess.run(
                    ["bsdtar", "-xpf", "-", "-C", str(root)], input=data, check=True
                )
            else:
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
                str(root / sysroot_lib / "libc.so.6"),
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
                str(root / sysroot_lib / "libstdc++.so.6"),
                str(root / sysroot_lib / "libgcc_s.so.1"),
                str(root / sysroot_lib / "libc.so.6"),
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
                *[flag for include in sysroot_includes for flag in ("-isystem", str(root / include))],
                "-isystem",
                str(builtin_include(compiler)),
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-shim.so",
                os.environ["DLFCN_GLIBC_SHIM_TEST_SOURCE"],
                "-o",
                str(shim_test),
            ],
            check=True,
        )
        # The initial-exec family: a defining module carrying both models, a
        # second module reaching the first one's TLS via initial-exec, and two
        # over-arena-sized modules, of which only the initial-exec one may
        # fail to load.
        ie_test = library_path / "libdlfcn-test-ie.so"
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-ie.so",
                os.environ["DLFCN_GLIBC_IE_TEST_SOURCE"],
                os.environ["DLFCN_GLIBC_IE_GD_TEST_SOURCE"],
                "-o",
                str(ie_test),
            ],
            check=True,
        )
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-ieref.so",
                os.environ["DLFCN_GLIBC_IE_REF_TEST_SOURCE"],
                str(ie_test),
                "-o",
                str(library_path / "libdlfcn-test-ieref.so"),
            ],
            check=True,
        )
        for big_name, big_flags in (
            ("libdlfcn-test-bigtls.so", []),
            ("libdlfcn-test-bigtlsie.so", ["-DBIG_TLS_IE"]),
        ):
            subprocess.run(
                [
                    *shlex.split(os.environ["DLFCN_CC"]),
                    "-fPIC",
                    "-fno-stack-protector",
                    "-shared",
                    "-nostdlib",
                    *big_flags,
                    "-Wl,--no-as-needed",
                    str(root / sysroot_lib / "libc.so.6"),
                    f"-Wl,-soname,{big_name}",
                    os.environ["DLFCN_GLIBC_BIG_TLS_TEST_SOURCE"],
                    "-o",
                    str(library_path / big_name),
                ],
                check=True,
            )
        # The scope-order family: a global interposer, the interposable
        # definition (plain and -Bsymbolic), and a caller built twice, loaded
        # once normally and once with RTLD_DEEPBIND.
        overridable = str(library_path / "libdlfcn-test-overridable.so")
        interpose = os.environ["DLFCN_GLIBC_INTERPOSE_TEST_SOURCE"]
        definition = os.environ["DLFCN_GLIBC_OVERRIDABLE_TEST_SOURCE"]
        caller = os.environ["DLFCN_GLIBC_CALLER_TEST_SOURCE"]
        for name, extras in (
            ("libdlfcn-test-interpose.so", [interpose]),
            ("libdlfcn-test-overridable.so", [definition]),
            ("libdlfcn-test-symbolic.so", [definition, "-Wl,-Bsymbolic"]),
            ("libdlfcn-test-caller.so", [caller, overridable]),
            ("libdlfcn-test-callerdeep.so", [caller, overridable]),
        ):
            subprocess.run(
                [
                    *shlex.split(os.environ["DLFCN_CC"]),
                    "-fPIC",
                    "-fno-stack-protector",
                    "-shared",
                    "-nostdlib",
                    "-Wl,--no-as-needed",
                    str(root / sysroot_lib / "libc.so.6"),
                    f"-Wl,-soname,{name}",
                    *extras,
                    "-o",
                    str(library_path / name),
                ],
                check=True,
            )
        # A SysV-hash-only image: the loader's --hash-style=sysv fallback.
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--hash-style=sysv",
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-sysv.so",
                os.environ["DLFCN_GLIBC_OVERRIDABLE_TEST_SOURCE"],
                "-o",
                str(library_path / "libdlfcn-test-sysv.so"),
            ],
            check=True,
        )
        # The versioned provider exists only for linking; the search path
        # carries the unversioned build, and the consumer's @V1 reference has
        # to accept it.
        version_script = root / "dlfcn-test.map"
        version_script.write_text("V1 {\n    global:\n        dlfcn_versioned_fn;\n    local: *;\n};\n")
        versioned_for_linking = root / "libdlfcn-test-versioned.so"
        for destination, extras in (
            (versioned_for_linking, [f"-Wl,--version-script={version_script}"]),
            (library_path / "libdlfcn-test-versioned.so", []),
        ):
            subprocess.run(
                [
                    *shlex.split(os.environ["DLFCN_CC"]),
                    "-fPIC",
                    "-fno-stack-protector",
                    "-shared",
                    "-nostdlib",
                    "-Wl,--no-as-needed",
                    str(root / sysroot_lib / "libc.so.6"),
                    "-Wl,-soname,libdlfcn-test-versioned.so",
                    os.environ["DLFCN_GLIBC_VERSIONED_TEST_SOURCE"],
                    *extras,
                    "-o",
                    str(destination),
                ],
                check=True,
            )
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-verconsumer.so",
                os.environ["DLFCN_GLIBC_VERSION_CONSUMER_TEST_SOURCE"],
                str(versioned_for_linking),
                "-o",
                str(library_path / "libdlfcn-test-verconsumer.so"),
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
                    str(root / sysroot_lib / "libc.so.6"),
                    f"-Wl,-soname,{lazy_name}",
                    os.environ["DLFCN_GLIBC_LAZY_TEST_SOURCE"],
                    "-o",
                    str(library_path / lazy_name),
                ],
                check=True,
            )
        (library_path / "libdlfcn-test-pci.so").symlink_to(
            root / sysroot_lib / "libpciaccess.so.0"
        )
        (library_path / "libdlfcn-test-vulkan.so").symlink_to(
            root / sysroot_lib / "libvulkan.so.1"
        )
        (library_path / "libz.so.1").symlink_to(
            root / sysroot_lib / "libz.so.1"
        )
        (library_path / "libgcc_s.so.1").symlink_to(
            root / sysroot_lib / "libgcc_s.so.1"
        )
        (library_path / "libstdc++.so.6").symlink_to(
            root / sysroot_lib / "libstdc++.so.6"
        )

        environment = os.environ.copy()
        environment.pop("DL_ELF_LIBRARY_PATH", None)
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(
            (str(root / "missing"), str(library_path))
        )
        # On glibc hosts, pick a small cached library so the smoke test can
        # exercise the /etc/ld.so.cache resolution end to end.
        environment["DLFCN_CACHE_PROBE"] = ""
        ldconfig = shutil.which("ldconfig") or shutil.which("ldconfig", path="/sbin:/usr/sbin")
        if ldconfig and os.path.exists("/etc/ld.so.cache"):
            listing = subprocess.run(
                [ldconfig, "-p"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if listing.returncode == 0:
                for candidate in ("libbz2.so.1", "liblzma.so.5", "libexpat.so.1"):
                    if f"\t{candidate} " in listing.stdout:
                        environment["DLFCN_CACHE_PROBE"] = candidate
                        break
        result = subprocess.run(
            [executable],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        if result.returncode:
            symbolize_fault(executable, result.stdout)
            rerun_under_gdb([executable], environment)

    print(result.stdout, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def rerun_under_gdb(command, environment):
    """A failed run reruns under gdb when one is around: the crash stops in
    the debugger before the process dies, and the batch script prints every
    thread's stack into the CI log."""
    gdb = shutil.which("gdb")
    if not gdb:
        return
    # The debugger itself must not resolve its libraries against the test's
    # LD_LIBRARY_PATH (glibc sysroots poison a dynamically linked gdb); only
    # the inferior gets it, through the debugger.
    launch_environment = {
        key: value for key, value in environment.items() if key != "LD_LIBRARY_PATH"
    }
    setup = []
    if "LD_LIBRARY_PATH" in environment:
        setup = ["-ex", "set environment LD_LIBRARY_PATH " + environment["LD_LIBRARY_PATH"]]
    replay = subprocess.run(
        [gdb, "--batch", "-quiet"]
        + setup
        + [
            "-ex", "run",
            "-ex", "info registers",
            "-ex", "thread apply all bt",
        ]
        + ["--args"]
        + command,
        env=launch_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(replay.stdout, file=sys.stderr)


def symbolize_fault(executable, text):
    """Resolve the crash reporter's bare pc values (addresses inside the
    static executable, invisible to the loader's dladdr) against the
    binary's own symbol table."""
    addresses = []
    for line in text.splitlines():
        match = re.fullmatch(r"solo test: (?:crash|frame) pc 0x([0-9a-f]+)", line)
        if match:
            addresses.append(int(match.group(1), 16))
    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if not addresses or not nm:
        return
    listing = subprocess.run(
        [nm, "-nC", "--defined-only", executable],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if listing.returncode != 0:
        return
    table = []
    for entry in listing.stdout.splitlines():
        fields = entry.split(" ", 2)
        if len(fields) == 3 and fields[1] in "tTwW":
            table.append((int(fields[0], 16), fields[2]))
    for address in addresses:
        index = bisect.bisect_right(table, (address, "￿")) - 1
        if index >= 0:
            value, name = table[index]
            print(f"solo symbolize: 0x{address:x} = {name}+0x{address - value:x}", file=sys.stderr)


if __name__ == "__main__":
    main()
