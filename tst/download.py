#!/usr/bin/env python3

import hashlib
import os
import sys
import urllib.request
from pathlib import Path


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: download.py URL SHA256 OUTPUT")

    url, expected, output_name = sys.argv[1:]
    output = Path(output_name)
    temporary = output.with_name(output.name + ".part")
    digest = hashlib.sha256()

    output.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "dlfcn-test/1"})
    try:
        with urllib.request.urlopen(request) as response, temporary.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                target.write(chunk)
        actual = digest.hexdigest()
        if actual != expected:
            raise RuntimeError(f"SHA-256 mismatch: {actual} != {expected}")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
