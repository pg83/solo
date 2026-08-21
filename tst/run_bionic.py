#!/usr/bin/env python3
"""Render through the Termux bionic Vulkan stack.

Downloads the current mesa-vulkan-icd-swrast closure from the Termux
repository, extracts it, points the demo at the lavapipe manifest, and
checks the reference image: the bionic personality end to end — bionic ELF
objects executing over the embedded musl runtime, no Android and no
container anywhere. Termux's mesa hardcodes its prefix as the temporary
directory, so the caller must provide a writable
/data/data/com.termux/files/usr/tmp.
"""

import hashlib
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from run_vulkan import EXPECTED_SHA256

MIRROR = "https://packages.termux.dev/apt/termux-main/"
PREFIX = "data/data/com.termux/files/usr"
ROOTS = ["mesa-vulkan-icd-swrast", "vulkan-loader", "libandroid-shmem"]


def fetch(url, destination):
    for attempt in range(8):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                destination.write_bytes(response.read())
            return
        except OSError as error:
            print(f"retrying {url}: {error}", file=sys.stderr)
    raise SystemExit(f"cannot download {url}")


def parse_index(text):
    packages, entry = {}, {}
    for line in text.splitlines():
        if not line:
            if "Package" in entry:
                packages[entry["Package"]] = entry
            entry = {}
        elif ": " in line and not line.startswith(" "):
            key, _, value = line.partition(": ")
            entry[key] = value
    if "Package" in entry:
        packages[entry["Package"]] = entry
    return packages


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: run_bionic.py EXECUTABLE OUTPUT")

    executable, output_name = sys.argv[1:]
    machine = platform.machine()
    output = Path(output_name)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="dlfcn-bionic-") as temporary:
        root = Path(temporary)
        index = root / "Packages"
        fetch(f"{MIRROR}dists/stable/main/binary-{machine}/Packages", index)
        packages = parse_index(index.read_text(errors="replace"))

        closure, queue = set(), list(ROOTS)
        while queue:
            name = queue.pop()
            if name in closure or name not in packages:
                continue
            closure.add(name)
            for dependency in re.split(r"[,|]", packages[name].get("Depends", "")):
                dependency = dependency.strip().split(" ")[0]
                if dependency:
                    queue.append(dependency)

        for name in sorted(closure):
            deb = root / Path(packages[name]["Filename"]).name
            fetch(MIRROR + packages[name]["Filename"], deb)
            digest = hashlib.sha256(deb.read_bytes()).hexdigest()
            if digest != packages[name].get("SHA256"):
                raise SystemExit(f"checksum mismatch for {deb.name}")
            data = subprocess.run(
                ["bsdtar", "-xOf", str(deb), "data.tar.*"],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            subprocess.run(
                ["bsdtar", "-xf", "-", "--no-same-owner", "-C", str(root)],
                input=data,
                check=True,
            )

        prefix = root / PREFIX
        manifests = sorted((prefix / "share/vulkan/icd.d").glob("lvp_icd*.json"))
        if not manifests:
            raise SystemExit("no lavapipe manifest in the Termux closure")
        manifest = root / "lvp_icd.json"
        manifest.write_text(
            manifests[0].read_text().replace(f"/{PREFIX}/lib", str(prefix / "lib"))
        )

        # Termux's mesa allocates through files under its own prefix.
        termux_tmp = Path("/") / PREFIX / "tmp"
        if not os.access(termux_tmp, os.W_OK):
            raise SystemExit(f"{termux_tmp} must exist and be writable")

        environment = os.environ.copy()
        for name in ("VK_DRIVER_FILES", "VK_ICD_FILENAMES"):
            environment.pop(name, None)
        environment["LD_LIBRARY_PATH"] = str(prefix / "lib")
        output.unlink(missing_ok=True)
        result = subprocess.run(
            [executable, "--driver", str(manifest), str(output)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        print(result.stdout, end="")
        if result.returncode:
            raise SystemExit(f"driver run failed: {result.returncode}")

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"rendered image mismatch: {digest}")
    print(f"bionic lavapipe: ok ({digest[:16]})")


if __name__ == "__main__":
    main()
