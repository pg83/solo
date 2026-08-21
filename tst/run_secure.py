#!/usr/bin/env python3
"""Assert the loader's AT_SECURE discipline.

The probe dlopens a bare name reachable only through LD_LIBRARY_PATH and
DL_ELF_LIBRARY_PATH. Run plain, the load must succeed; run set-uid root —
which puts the kernel's AT_SECURE into the auxv — the same environment must
be ignored and the load must fail. Needs passwordless sudo for the set-uid
half; without it only the plain half runs.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run_probe(probe, environment):
    result = subprocess.run(
        [str(probe), "libdlfcn-secure-target.so"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise SystemExit(f"probe failed: {result.returncode}: {result.stdout}")
    return result.stdout.strip()


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: run_secure.py OUTPUT PROBE TARGET")

    output = Path(sys.argv[1])
    probe = Path(sys.argv[2])
    target = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = []

    # Temp filesystems often mount nosuid; stage next to the build output.
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="secure-") as temporary:
        root = Path(temporary)
        shutil.copy2(target, root / "libdlfcn-secure-target.so")

        environment = os.environ.copy()
        environment["LD_LIBRARY_PATH"] = str(root)
        environment["DL_ELF_LIBRARY_PATH"] = str(root)

        plain = run_probe(probe, environment)
        lines.append(f"plain: {plain}")
        if plain != "secure=0 loaded":
            raise SystemExit(f"plain run must load through the environment: {plain}")

        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            lines.append("set-uid half skipped: no passwordless sudo")
        else:
            elevated = root / "secure_probe"
            shutil.copy2(probe, elevated)
            subprocess.run(["sudo", "chown", "root:root", str(elevated)], check=True)
            subprocess.run(["sudo", "chmod", "4755", str(elevated)], check=True)

            secure = run_probe(elevated, environment)
            lines.append(f"set-uid: {secure}")
            subprocess.run(["sudo", "rm", "-f", str(elevated)], check=True)
            if secure != "secure=1 not-loaded":
                raise SystemExit(f"a secure process honored the environment: {secure}")

    text = "\n".join(lines) + "\n"
    print(text, end="")
    output.write_text(text)


if __name__ == "__main__":
    main()
