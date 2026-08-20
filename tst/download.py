#!/usr/bin/env python3

import hashlib
import os
import random
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ATTEMPTS = 8


def fetch(url, temporary):
    digest = hashlib.sha256()
    request = urllib.request.Request(url, headers={"User-Agent": "dlfcn-test/1"})
    with urllib.request.urlopen(request) as response, temporary.open("wb") as target:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            target.write(chunk)
    return digest.hexdigest()


def fromMirror(mirror, expected, output, temporary):
    candidate = mirror / output.name

    try:
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError:
        return False
    if digest != expected:
        print(f"download.py: {candidate}: SHA-256 mismatch, falling back to the network", file=sys.stderr)
        return False

    shutil.copyfile(candidate, temporary)
    os.replace(temporary, output)

    return True


def main():
    arguments = sys.argv[1:]
    mirror = None

    if len(arguments) >= 2 and arguments[0] == "--mirror":
        mirror = Path(arguments[1])
        arguments = arguments[2:]
    if len(arguments) != 3:
        raise SystemExit("usage: download.py [--mirror DIR] URL SHA256 OUTPUT")

    url, expected, output_name = arguments
    output = Path(output_name)
    temporary = output.with_name(output.name + ".part")

    output.parent.mkdir(parents=True, exist_ok=True)
    if mirror and fromMirror(mirror, expected, output, temporary):
        return
    try:
        # snapshot.debian.org resets connections under parallel load; back
        # off with jitter so a whole build graph of downloads gets through.
        for attempt in range(ATTEMPTS):
            try:
                actual = fetch(url, temporary)
                break
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                if attempt == ATTEMPTS - 1:
                    raise
                delay = min(2**attempt, 30) + random.random()
                print(f"download.py: {url}: {error}; retrying in {delay:.0f}s", file=sys.stderr)
                time.sleep(delay)
        if actual != expected:
            raise RuntimeError(f"SHA-256 mismatch: {actual} != {expected}")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
