#!/usr/bin/env python3
"""A whole system booted in qemu with solo as the dynamic linker.

Takes the same stripped-of-glibc rootfs the chroot smoke builds, packs it
into an initramfs, and boots it under qemu with the host's kernel: PID 1 is
the distribution's own shell, kernel-loaded with solo as its PT_INTERP, and
every command of the boot battery runs the same way. No block devices, no
modules — the whole userland lives in the initramfs.

usage: qemu_smoke.py OUTPUT ARCHIVE
environment: DLFCN_SOLO, DLFCN_KERNEL, DLFCN_QEMU (default qemu-system-x86_64)
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rootfs_smoke import interpreter_path, strip_glibc, unpack

INIT = """#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export TERM=dumb
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo SOLO-QEMU-BOOT
echo "shell $((6*7))"
echo hello world | sed "s/\\(hello\\) \\(world\\)/\\2 \\1/"
grep -c . /etc/os-release > /dev/null && echo grep-ok
if [ -x /usr/bin/dpkg ]; then
    dpkg -l > /dev/null && echo package-manager-ok
fi
if [ -x /usr/bin/rpm ]; then
    rpm -q bash > /dev/null && echo package-manager-ok
fi
echo SOLO-QEMU-OK
echo o > /proc/sysrq-trigger
sleep 30
"""


def newc_record(name, mode, rdevmajor, rdevminor):
    """One hand-written cpio record: bsdtar cannot archive device nodes an
    unprivileged build never created, but the kernel is happy to read one."""
    encoded = name.encode() + b"\0"
    fields = [
        1,  # inode
        mode,
        0,  # uid
        0,  # gid
        1,  # nlink
        0,  # mtime
        0,  # filesize
        0,  # devmajor
        0,  # devminor
        rdevmajor,
        rdevminor,
        len(encoded),
        0,  # check
    ]
    record = b"070701" + b"".join(f"{value:08X}".encode() for value in fields) + encoded

    return record + b"\0" * ((4 - len(record) % 4) % 4)


def device_segment():
    return newc_record("dev/console", 0o020600, 5, 1) + newc_record("TRAILER!!!", 0, 0, 0)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)

    output = Path(sys.argv[1])
    archive = sys.argv[2]
    solo = os.environ["DLFCN_SOLO"]
    kernel = os.environ["DLFCN_KERNEL"]
    qemu = os.environ.get("DLFCN_QEMU", "qemu-system-x86_64")

    with tempfile.TemporaryDirectory(prefix="dlfcn-qemu-") as temporary:
        root = Path(temporary) / "root"
        root.mkdir()
        unpack(archive, root)

        interpreter = interpreter_path(root / "usr/bin/ls")
        strip_glibc(root)

        target = root / interpreter.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(solo, target)

        init = root / "init"
        init.write_text(INIT)
        init.chmod(0o755)
        (root / "dev").mkdir(exist_ok=True)

        initrd = Path(temporary) / "initrd.gz"
        packed = subprocess.run(
            ["bsdtar", "--format", "newc", "--uid", "0", "--gid", "0", "-cf", "-", "-C", str(root), "."],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        subprocess.run(
            ["gzip", "-1"],
            check=True,
            input=packed + device_segment(),
            stdout=initrd.open("wb"),
        )

        boot = subprocess.run(
            [
                qemu,
                "-nographic",
                "-no-reboot",
                "-m", "1024",
                "-accel", "kvm",
                "-accel", "tcg",
                "-kernel", kernel,
                "-initrd", str(initrd),
                "-append", "console=ttyS0 rdinit=/init panic=-1 sysrq_always_enabled=1 loglevel=4",
            ],
            check=False,
            text=True,
            errors="replace",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
        )

    print(boot.stdout, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(boot.stdout)
    for needle in ("SOLO-QEMU-BOOT", "shell 42", "world hello", "grep-ok", "package-manager-ok", "SOLO-QEMU-OK"):
        if needle not in boot.stdout:
            raise SystemExit(f"qemu boot misses: {needle}")


if __name__ == "__main__":
    main()
