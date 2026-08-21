#!/usr/bin/env python3
"""A distribution rootfs with its glibc cut out, running on solo as ld.so.

Unpacks a downloaded base layer (an ubuntu-base tarball or a Fedora OCI
archive), deletes every glibc artifact — the dynamic linker included —
plants solo at the path the distribution's binaries name in PT_INTERP, and
runs the distribution's own coreutils and package manager inside an
unprivileged chroot. The kernel loads each binary itself and starts solo as
the interpreter; no glibc code exists in the tree at all.

usage: rootfs_smoke.py OUTPUT ARCHIVE...
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

GLIBC_LIBRARIES = [
    "ld-linux*.so*",
    "libc.so*",
    "libm.so*",
    "libmvec*",
    "libpthread.so*",
    "libdl.so*",
    "librt.so*",
    "libutil.so*",
    "libanl.so*",
    "libresolv.so*",
    "libnsl.so*",
    "libnss_*.so*",
    "libBrokenLocale*",
    "libc_malloc_debug*",
    "libthread_db*",
    "libmemusage*",
    "libpcprofile*",
]


def unpack(archive, root):
    """The base layer: ubuntu-base is the rootfs tarball itself, a Fedora
    OCI archive holds it as its one compressed layer blob."""
    if ".oci." in archive:
        with tempfile.TemporaryDirectory(prefix="dlfcn-oci-") as oci:
            subprocess.run(["bsdtar", "-xf", archive, "-C", oci], check=True)
            blobs = sorted(
                Path(oci).glob("blobs/*/*"),
                key=lambda blob: blob.stat().st_size,
            )
            subprocess.run(
                ["bsdtar", "-xf", str(blobs[-1]), "-C", str(root)],
                check=True,
            )
        return

    subprocess.run(["bsdtar", "-xf", archive, "-C", str(root)], check=True)


def interpreter_path(executable):
    """The PT_INTERP string of a distribution binary: where the kernel will
    look for the dynamic linker, and so where solo must sit."""
    with open(executable, "rb") as elf:
        header = elf.read(64)
        (phoff,) = struct.unpack_from("<Q", header, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", header, 0x36)
        elf.seek(phoff)
        table = elf.read(phentsize * phnum)
        for index in range(phnum):
            (p_type,) = struct.unpack_from("<I", table, index * phentsize)
            if p_type == 3:  # PT_INTERP
                (offset,) = struct.unpack_from("<Q", table, index * phentsize + 8)
                (size,) = struct.unpack_from("<Q", table, index * phentsize + 32)
                elf.seek(offset)
                return elf.read(size).rstrip(b"\0").decode()
    raise SystemExit(f"{executable}: no PT_INTERP")


def strip_glibc(root):
    for libdir in ("usr/lib", "usr/lib64", "usr/lib/x86_64-linux-gnu", "usr/lib/aarch64-linux-gnu"):
        base = root / libdir
        if not base.is_dir():
            continue
        # Fedora ships its library directories read-only.
        base.chmod(0o755)
        for pattern in GLIBC_LIBRARIES:
            for path in base.glob(pattern):
                path.unlink()
        for data in ("gconv", "audit"):
            shutil.rmtree(base / data, ignore_errors=True)


def chroot_run(root, command, environment):
    return subprocess.run(
        ["unshare", "-r", "chroot", str(root), *command],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        timeout=300,
    )


def check(log, root, command, environment, needle):
    result = chroot_run(root, command, environment)
    line = f"[{result.returncode}] {' '.join(command)}"
    log.append(line + "\n" + result.stdout.strip())
    if result.returncode or needle not in result.stdout:
        print("\n".join(log), file=sys.stderr)
        raise SystemExit(f"rootfs check failed: {line}, wanted {needle!r}")


def exercise(log, archive, solo):
    with tempfile.TemporaryDirectory(prefix="dlfcn-rootfs-") as temporary:
        root = Path(temporary) / "root"
        root.mkdir()
        unpack(archive, root)

        # A shell names the interpreter path before glibc goes away.
        interpreter = interpreter_path(root / "usr/bin/ls")
        strip_glibc(root)

        target = root / interpreter.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(solo, target)

        # A controlled environment: the checks must not inherit the host's
        # locale or search paths.
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "TERM": "dumb",
        }

        log.append(f"== {os.path.basename(archive)} via {interpreter}")
        check(log, root, ["/bin/sh", "-c", "echo shell $((6*7))"], environment, "shell 42")
        check(log, root, ["/usr/bin/ls", "/usr"], environment, "bin")
        check(log, root, ["/usr/bin/cat", "/etc/os-release"], environment, "ID")
        check(log, root, ["/bin/sh", "-c", "grep -c ^ /etc/os-release"], environment, "")
        check(log, root, ["/bin/sh", "-c", 'echo hello world | sed "s/\\(hello\\) \\(world\\)/\\2 \\1/"'], environment, "world hello")
        check(log, root, ["/usr/bin/find", "/etc", "-maxdepth", "1", "-name", "os-release"], environment, "/etc/os-release")

        if (root / "usr/bin/dpkg").exists():
            check(log, root, ["/usr/bin/dpkg", "-l"], environment, "libc6")
            check(log, root, ["/usr/bin/apt-get", "check"], environment, "")
        if (root / "usr/bin/rpm").exists():
            check(log, root, ["/usr/bin/rpm", "-q", "bash"], environment, "bash-")
        if (root / "usr/bin/dnf").exists():
            check(log, root, ["/usr/bin/dnf", "--version"], environment, "dnf5 version")


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)

    output = Path(sys.argv[1])
    archives = sys.argv[2:]
    solo = os.environ["DLFCN_SOLO"]
    log = []

    # An unprivileged user namespace is the whole mechanism; containerized
    # CI machines that forbid nested namespaces skip honestly.
    probe = subprocess.run(
        ["unshare", "-r", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode:
        log.append("SKIP: user namespaces are unavailable")
    else:
        for archive in archives:
            exercise(log, archive, solo)

    text = "\n".join(log) + "\n"
    print(text, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)


if __name__ == "__main__":
    main()
