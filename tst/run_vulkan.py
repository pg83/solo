#!/usr/bin/env python3

import hashlib
import subprocess
import sys
from pathlib import Path


EXPECTED_SHA256 = "9abbdcc0f3290f075f404ece8b4fd2966c46e97e5f8e5733221632891b9d1648"


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: run_vulkan.py EXECUTABLE ICD OUTPUT")

    executable, manifest_name, output_name = sys.argv[1:]
    manifest = Path(manifest_name)
    output = Path(output_name)

    if not manifest.is_file():
        raise SystemExit(f"lavapipe ICD manifest not found: {manifest}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    result = subprocess.run(
        [executable, "--driver", str(manifest), str(output)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)

    data = output.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"unexpected PNG SHA-256: {digest}")

    print(f"verified {output}: {digest}")


if __name__ == "__main__":
    main()
