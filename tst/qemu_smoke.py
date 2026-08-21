#!/usr/bin/env python3
"""A whole system booted in qemu with solo as the dynamic linker.

Takes the same stripped-of-glibc rootfs the chroot smoke builds, packs it
into an initramfs, and boots it under qemu with the host's kernel: no block
devices and no modules, the whole userland in RAM, every process
kernel-loaded with solo as its PT_INTERP. With systemd and dbus packages
overlaid, PID 1 is the real systemd: it mounts the API filesystems, runs
sysusers, journald, the serial getty, and a battery unit that interrogates
the system bus and powers the machine off. Without packages, PID 1 is the
distribution's shell running the same battery directly.

usage: qemu_smoke.py OUTPUT ARCHIVE [DEB...]
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
/usr/local/bin/solo-battery
echo o > /proc/sysrq-trigger
sleep 30
"""

BATTERY = """#!/bin/sh
echo SOLO-QEMU-BATTERY
echo "shell $((6*7))"
echo hello world | sed "s/\\(hello\\) \\(world\\)/\\2 \\1/"
grep -c . /etc/os-release > /dev/null && echo grep-ok
if [ -x /usr/bin/dpkg ]; then
    dpkg -l > /dev/null && echo package-manager-ok
fi
if [ -x /usr/bin/rpm ]; then
    rpm -q bash > /dev/null && echo package-manager-ok
fi
if [ -x /usr/bin/busctl ]; then
    busctl list --no-pager --no-legend | grep -q freedesktop && echo dbus-ok
    systemctl list-units --type=service --state=running --no-legend --no-pager
fi
echo SOLO-QEMU-OK
"""

BATTERY_UNIT = """[Unit]
Description=solo boot battery
After=multi-user.target

[Service]
Type=oneshot
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/usr/local/bin/solo-battery
ExecStartPost=/usr/bin/systemctl --no-block poweroff

[Install]
WantedBy=multi-user.target
"""

PLAIN_NEEDLES = ["SOLO-QEMU-BOOT", "shell 42", "world hello", "grep-ok", "package-manager-ok", "SOLO-QEMU-OK"]
SYSTEMD_NEEDLES = ["shell 42", "world hello", "package-manager-ok", "dbus-ok", "systemd-journald.service", "SOLO-QEMU-OK"]


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


def overlay_packages(root, packages):
    """Unpacked straight over the tree, with the pre-usr-merge paths some
    packages still use rewritten onto the merged layout — bsdtar will not
    extract through the distribution's lib and bin symlinks."""
    for package in packages:
        data = subprocess.run(
            ["bsdtar", "-xOf", package, "data.tar.*"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        subprocess.run(
            [
                "bsdtar", "-xf", "-", "-C", str(root),
                "-s", "#^\\./lib/#./usr/lib/#",
                "-s", "#^\\./lib64/#./usr/lib64/#",
                "-s", "#^\\./bin/#./usr/bin/#",
                "-s", "#^\\./sbin/#./usr/sbin/#",
            ],
            check=True,
            input=data,
        )


def install_systemd_boot(root):
    """The pieces a package postinst would have provided: an empty machine
    identity for a transient one, the battery unit enabled at multi-user,
    and the battery on the path. Users and groups come from systemd's own
    sysusers service at boot."""
    (root / "etc/machine-id").write_text("")
    (root / "etc/hostname").write_text("solo\n")

    battery = root / "usr/local/bin/solo-battery"
    battery.parent.mkdir(parents=True, exist_ok=True)
    battery.write_text(BATTERY)
    battery.chmod(0o755)

    unit = root / "etc/systemd/system/solo-battery.service"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(BATTERY_UNIT)

    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    (wants / "solo-battery.service").symlink_to("/etc/systemd/system/solo-battery.service")


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)

    output = Path(sys.argv[1])
    archive = sys.argv[2]
    packages = sys.argv[3:]
    solo = os.environ["DLFCN_SOLO"]
    kernel = os.environ["DLFCN_KERNEL"]
    qemu = os.environ.get("DLFCN_QEMU", "qemu-system-x86_64")

    with tempfile.TemporaryDirectory(prefix="dlfcn-qemu-") as temporary:
        root = Path(temporary) / "root"
        root.mkdir()
        unpack(archive, root)
        overlay_packages(root, packages)

        interpreter = interpreter_path(root / "usr/bin/ls")
        strip_glibc(root)

        target = root / interpreter.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(solo, target)

        if packages:
            install_systemd_boot(root)
            init = "rdinit=/usr/lib/systemd/systemd systemd.unit=multi-user.target systemd.show_status=1"
            needles = SYSTEMD_NEEDLES
        else:
            script = root / "init"
            battery = root / "usr/local/bin/solo-battery"
            battery.parent.mkdir(parents=True, exist_ok=True)
            battery.write_text(BATTERY)
            battery.chmod(0o755)
            script.write_text(INIT)
            script.chmod(0o755)
            init = "rdinit=/init"
            needles = PLAIN_NEEDLES
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
                "-append", f"console=ttyS0 {init} panic=-1 sysrq_always_enabled=1 loglevel=4",
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
    for needle in needles:
        if needle not in boot.stdout:
            raise SystemExit(f"qemu boot misses: {needle}")


if __name__ == "__main__":
    main()
