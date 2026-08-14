#!/usr/bin/env python3

import os
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

        environment = os.environ.copy()
        environment["DL_ELF_LIBRARY_PATH"] = str(root / "usr" / "lib")
        result = subprocess.run(
            [executable, str(root)],
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
