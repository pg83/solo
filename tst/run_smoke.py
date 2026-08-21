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
        # The caller-RUNPATH family: a host carrying -rpath '$ORIGIN/runpath'
        # loads a sibling by bare name that sits outside every other search
        # path, so the load succeeds only when the caller's DT_RUNPATH joins
        # the search.
        runpath_directory = library_path / "runpath"
        runpath_directory.mkdir()
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                # -O2 turns the host's dlopen forwarder into a tail jump,
                # pinning the relocation-time caller attribution.
                "-O2",
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                "-Wl,--enable-new-dtags",
                "-Wl,-rpath,$ORIGIN/runpath",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-runpath-host.so",
                os.environ["DLFCN_GLIBC_RUNPATH_HOST_TEST_SOURCE"],
                "-o",
                str(library_path / "libdlfcn-test-runpath-host.so"),
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
                "-Wl,-soname,libdlfcn-test-runpath-sibling.so",
                os.environ["DLFCN_GLIBC_RUNPATH_SIBLING_TEST_SOURCE"],
                "-o",
                str(runpath_directory / "libdlfcn-test-runpath-sibling.so"),
            ],
            check=True,
        )
        # The same host with old-dtags: a caller carrying DT_RPATH only.
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-fPIC",
                "-fno-stack-protector",
                "-shared",
                "-nostdlib",
                "-Wl,--no-as-needed",
                "-Wl,--disable-new-dtags",
                "-Wl,-rpath,$ORIGIN/runpath",
                str(root / sysroot_lib / "libc.so.6"),
                "-Wl,-soname,libdlfcn-test-rpath-host.so",
                os.environ["DLFCN_GLIBC_RUNPATH_HOST_TEST_SOURCE"],
                "-o",
                str(library_path / "libdlfcn-test-rpath-host.so"),
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
        else:
            # ldd's arrow format, with every provenance the loader knows:
            # a mapped file, a bridged soname, and a static provider.
            trace = subprocess.run(
                [executable],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={**environment, "LD_TRACE_LOADED_OBJECTS": "1"},
            )
            for needle in (
                "libdlfcn-test-glibc.so => /",
                "libc.so.6 => the glibc ABI bridge",
                "=> a static provider linked into the executable",
            ):
                if needle not in trace.stdout:
                    raise SystemExit(f"LD_TRACE_LOADED_OBJECTS misses: {needle}")
            if trace.returncode:
                raise SystemExit(f"traced run failed: {trace.returncode}")
            run_solo_checks(root, sysroot_lib, environment)

    print(result.stdout, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def run_solo_checks(root, sysroot_lib, environment):
    """A whole glibc executable through the solo command: linked against the
    sysroot's own crt objects and libc.so.6, so its _start is glibc's crt and
    startup runs through the bridge's __libc_start_main."""
    solo = os.environ["DLFCN_SOLO"]
    # Linking an executable against a bare libc.so.6 leaves ld.so's
    # GLIBC_PRIVATE half unresolved; glibc hosts quietly find their own
    # ld-linux for it, musl hosts have none, so the sysroot's is explicit.
    ld_so = sorted((root / sysroot_lib).glob("ld-linux-*.so*"))
    if not ld_so:
        raise SystemExit(f"no ld-linux in the sysroot under {sysroot_lib}")
    # Both link models: a PIE the loader places anywhere, and a non-PIE that
    # owns its fixed link-time addresses — which is why solo itself is
    # static-PIE.
    guests = []
    for suffix, model, crt1 in (
        ("", ["-fPIE", "-pie"], "Scrt1.o"),
        ("-exec", ["-fno-pie", "-no-pie"], "crt1.o"),
    ):
        guest = root / f"dlfcn-test-guest{suffix}"
        subprocess.run(
            [
                *shlex.split(os.environ["DLFCN_CC"]),
                "-O2",
                *model,
                "-fno-stack-protector",
                "-nostdlib",
                "-Wl,--no-as-needed",
                str(root / sysroot_lib / crt1),
                str(root / sysroot_lib / "crti.o"),
                os.environ["DLFCN_GLIBC_GUEST_TEST_SOURCE"],
                str(root / sysroot_lib / "libc.so.6"),
                str(ld_so[0]),
                str(root / sysroot_lib / "crtn.o"),
                "-o",
                str(guest),
            ],
            check=True,
        )
        guests.append(guest)

    guest_environment = {**environment, "SOLO_GUEST_ENV": "smoke-value"}
    for command in (
        [solo, "run", str(guests[0]), "alpha", "beta"],
        [solo, str(guests[0]), "alpha", "beta"],
        [solo, "run", str(guests[1]), "alpha", "beta"],
    ):
        run = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=guest_environment,
        )
        for needle in (
            "guest init",
            "guest main argc=3",
            "guest argv alpha",
            "guest argv beta",
            "guest stdout env=smoke-value",
            "guest environ present",
            "guest atexit",
        ):
            if needle not in run.stdout:
                print(run.stdout, file=sys.stderr)
                raise SystemExit(f"solo run misses: {needle}")
        if run.returncode != 42:
            print(run.stdout, file=sys.stderr)
            raise SystemExit(f"solo run exited {run.returncode}, wanted the guest's 42")

    ldd = subprocess.run(
        [solo, "ldd", str(guests[0])],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=guest_environment,
    )
    if "libc.so.6 => the glibc ABI bridge" not in ldd.stdout:
        print(ldd.stdout, file=sys.stderr)
        raise SystemExit("solo ldd misses the bridged libc.so.6 line")
    if "guest main" in ldd.stdout:
        raise SystemExit("solo ldd ran the guest instead of only tracing it")
    if ldd.returncode:
        print(ldd.stdout, file=sys.stderr)
        raise SystemExit(f"solo ldd exited {ldd.returncode}")


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
        key: value
        for key, value in environment.items()
        if key not in ("LD_LIBRARY_PATH", "LD_DEBUG", "LD_DEBUG_OUTPUT")
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
