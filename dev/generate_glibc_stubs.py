#!/usr/bin/env python3
"""Collect every exported Arch glibc symbol into the checked-in symbol table."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, order=True)
class Export:
    name: str
    version: str
    kind: str
    size: int


def quote(value: str) -> str:
    return json.dumps(value)


def source(package: Path) -> str:
    if package.name.endswith(".deb"):
        return "Debian " + package.name.removesuffix(".deb").replace("_", " ")
    name = package.name.split(".pkg.")[0].removesuffix("-x86_64")

    return "Arch " + name.replace("-", " ", 1)


def exports(path: Path) -> set[Export]:
    output = subprocess.check_output(
        ["llvm-readelf", "--dyn-symbols", "--wide", str(path)],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    result: set[Export] = set()

    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 8 or columns[6] == "UND":
            continue
        kind = columns[3]
        if kind not in {"FUNC", "IFUNC", "OBJECT", "TLS"}:
            continue
        name = columns[7]
        if "@GLIBC_" not in name:
            continue
        name, version = name.split("@", 1)
        version = version.lstrip("@")
        if name.startswith("GLIBC_"):
            continue
        result.add(Export(name, version, kind, int(columns[2])))

    return result


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_glibc_stubs.py GLIBC_PACKAGE OUTPUT_JSON")

    package = Path(sys.argv[1])
    output = Path(sys.argv[2])

    with tempfile.TemporaryDirectory(prefix="dlfcn-glibc-") as temporary:
        root = Path(temporary)
        if package.name.endswith(".deb"):
            data = subprocess.check_output(["bsdtar", "-xOf", str(package), "data.tar.*"])
            subprocess.run(["bsdtar", "-xpf", "-", "-C", str(root)], input=data, check=True)
        else:
            subprocess.run(
                ["bsdtar", "-xpf", str(package), "-C", str(root)],
                check=True,
            )
        found: set[Export] = set()
        libraries = [
            *(root / "usr" / "lib").glob("*.so*"),
            *(root / "usr" / "lib").glob("*-linux-gnu/*.so*"),
        ]
        for path in sorted(libraries):
            if not path.is_file() or path.read_bytes()[:4] != b"\x7fELF":
                continue
            found.update(exports(path))

    lines = ["{", f'    "source": {quote(source(package))},', '    "symbols": [']
    entries = []
    for symbol in sorted(found):
        kind = "function" if symbol.kind in {"FUNC", "IFUNC"} else symbol.kind.lower()
        entries.append(
            "        "
            + json.dumps({
                "name": symbol.name,
                "version": symbol.version,
                "kind": kind,
                "size": symbol.size,
            })
        )
    lines.append(",\n".join(entries))
    lines.extend(["    ]", "}", ""])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))
    print(f"generated {len(found)} versioned glibc providers in {output}")


if __name__ == "__main__":
    main()
