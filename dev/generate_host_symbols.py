#!/usr/bin/env python3
"""Collect the identity providers for the embedded musl into the symbol table."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


MUSL_SOURCE = "musl 1.2.5"

NON_DIRECT_SYMBOLS = {
    "__tls_get_addr",
    "dladdr",
    "dlclose",
    "dlerror",
    "dlinfo",
    "dlopen",
    "dlsym",
}

PROCESS_SYMBOLS = {
    "__libc_start_main",
    "_fini",
    "_init",
}


def defined_symbols(path: Path, dynamic: bool = False) -> set[str]:
    arguments = [
        "llvm-readelf",
        "--dyn-symbols" if dynamic else "--symbols",
        str(path),
    ]
    output = subprocess.check_output(
        arguments,
        text=True,
        stderr=subprocess.DEVNULL,
    )
    result: set[str] = set()
    for line in output.splitlines():
        fields = line.split()

        if (
            len(fields) == 8
            and fields[0].endswith(":")
            and fields[4] in ("GLOBAL", "WEAK")
            and fields[5] in ("DEFAULT", "PROTECTED")
            and fields[6] != "UND"
        ):
            result.add(fields[7])
    return result


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: generate_host_symbols.py MUSL_LIBC_A MUSL_LIBC_SO OUTPUT_JSON"
        )

    available = defined_symbols(Path(sys.argv[1]))
    public = defined_symbols(Path(sys.argv[2]), dynamic=True)
    direct = sorted((available & public) - NON_DIRECT_SYMBOLS - PROCESS_SYMBOLS)

    lines = [
        "{",
        f'    "source": {json.dumps(MUSL_SOURCE)},',
        '    "symbols": [',
        ",\n".join(f"        {json.dumps(symbol)}" for symbol in direct),
        "    ]",
        "}",
        "",
    ]

    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))
    print(f"collected {len(direct)} musl identity providers in {output}")


if __name__ == "__main__":
    main()
