#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: run_pthread_bridge.py EXECUTABLE OUTPUT")

    executable, output_name = sys.argv[1:]
    output = Path(output_name)
    result = subprocess.run(
        [executable],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )

    print(result.stdout, end="")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
