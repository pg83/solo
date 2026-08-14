#!/usr/bin/env python3
"""Generate the hard-coded identity providers for the embedded musl."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def archive_symbols(archive: Path) -> set[str]:
    output = subprocess.check_output(
        ["llvm-readelf", "--symbols", str(archive)],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    result: set[str] = set()
    for line in output.splitlines():
        fields = line.split()

        if len(fields) == 8 and fields[0].endswith(":") and fields[4] in ("GLOBAL", "WEAK") and fields[5] in ("DEFAULT", "PROTECTED") and fields[6] != "UND":
            result.add(fields[7])
    return result


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_host_symbols.py MUSL_LIBC_A OUTPUT_CPP")

    direct = sorted(archive_symbols(Path(sys.argv[1])))

    lines = [
        "// Generated from musl 1.2.5 by generate_host_symbols.py.",
        '#include "musl_symbols.h"',
        "",
        'extern "C" {',
    ]
    for symbol in direct:
        escaped = symbol.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            f"    extern void* {escaped};"
        )
    lines.extend([
        "}",
        "",
        "const MuslSymbol MUSL_SYMBOLS[] = {",
    ])
    for symbol in direct:
        escaped = symbol.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            f'    {{"{escaped}", &{escaped}}},'
        )
    lines.extend([
        "};",
        "",
        "const size_t MUSL_SYMBOL_COUNT = sizeof(MUSL_SYMBOLS) / sizeof(MUSL_SYMBOLS[0]);",
        "",
    ])

    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))
    print(f"generated {len(direct)} musl identity providers in {output}")


if __name__ == "__main__":
    main()
