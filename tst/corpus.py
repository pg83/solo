#!/usr/bin/env python3
"""Load every corpus library through SoLo and report glibc ABI coverage.

Every .so of the extracted packages is loaded eagerly in a fresh process, so
each import is exercised by relocation. Imports that resolve into abort or
inaccessible-object stubs are collected from the bridge's debug output; the
result is a text report and an lcov trace mapped onto the lines of
lib/glibc_symbols.json, so the coverage service shows which ABI entries the
corpus demands and which of them only have stubs.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

STUB_LINE = "glibc bridge: resolved fallback "
OBJECT_LINE = "glibc bridge: unimplemented data object "

SHT_DYNSYM = 11
SHT_GNU_VERSYM = 0x6FFFFFFF
SHT_GNU_VERNEED = 0x6FFFFFFE


def sections(data):
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    out = []
    for index in range(shnum):
        raw = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        out.append({"type": raw[1], "offset": raw[4], "size": raw[5], "link": raw[6], "entsize": raw[9]})
    return out


def version_names(data, table, verneed):
    names = {}
    if verneed is None:
        return names
    strings = table[verneed["link"]]
    offset = verneed["offset"]
    while True:
        _, count, _, aux, next_need = struct.unpack_from("<HHIII", data, offset)
        aux_offset = offset + aux
        for _ in range(count):
            _, _, other, name, next_aux = struct.unpack_from("<IHHII", data, aux_offset)
            end = data.index(b"\0", strings["offset"] + name)
            names[other & 0x7FFF] = data[strings["offset"] + name : end].decode()
            if not next_aux:
                break
            aux_offset += next_aux
        if not next_need:
            break
        offset += next_need
    return names


def glibc_imports(path):
    """The library's undefined symbols with a glibc/GCC version."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    table = sections(data)
    dynsym = next((s for s in table if s["type"] == SHT_DYNSYM), None)
    versym = next((s for s in table if s["type"] == SHT_GNU_VERSYM), None)
    verneed = next((s for s in table if s["type"] == SHT_GNU_VERNEED), None)
    if dynsym is None:
        return set()
    strings = table[dynsym["link"]]
    names = version_names(data, table, verneed)
    imports = set()
    count = dynsym["size"] // dynsym["entsize"]
    for index in range(1, count):
        name, _, _, shndx = struct.unpack_from("<IBBH", data, dynsym["offset"] + index * dynsym["entsize"])
        if shndx != 0 or not name:
            continue
        version = None
        if versym is not None:
            (raw,) = struct.unpack_from("<H", data, versym["offset"] + index * 2)
            version = names.get(raw & 0x7FFF)
        if version is None or not version.startswith(("GLIBC_", "GCC_")):
            continue
        end = data.index(b"\0", strings["offset"] + name)
        imports.add(f"{data[strings['offset'] + name:end].decode()}@{version}")
    return imports


def inventory_lines(path):
    """Map name@version to its line number in glibc_symbols.json."""
    lines = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip().rstrip(",")
        if not line.startswith('{"name"'):
            continue
        entry = json.loads(line)
        lines[f"{entry['name']}@{entry['version']}"] = number
    return lines


def load(driver, library, root):
    environment = os.environ.copy()
    environment["DL_GLIBC_STUB_DEBUG"] = "1"
    environment.pop("DL_ELF_LIBRARY_PATH", None)
    environment["LD_LIBRARY_PATH"] = str(root / "usr" / "lib")
    result = subprocess.run(
        [driver, str(library)],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stubs = set()
    error = None
    for line in result.stdout.splitlines():
        if line.startswith(STUB_LINE):
            stubs.add(line[len(STUB_LINE) :].strip())
        elif line.startswith(OBJECT_LINE):
            stubs.add(line[len(OBJECT_LINE) :].split(" at ")[0].strip())
        elif error is None and line.strip():
            error = line.strip()
    return result.returncode == 0, stubs, error


def main():
    if len(sys.argv) < 6:
        raise SystemExit("usage: corpus.py REPORT LCOV DRIVER SYMBOLS_JSON ARCHIVE...")

    report_path = Path(sys.argv[1])
    lcov_path = Path(sys.argv[2])
    driver = sys.argv[3]
    inventory = inventory_lines(Path(sys.argv[4]))
    archives = sys.argv[5:]

    with tempfile.TemporaryDirectory(prefix="dlfcn-corpus-") as temporary:
        root = Path(temporary)
        for archive in archives:
            subprocess.run(["bsdtar", "-xpf", archive, "-C", str(root)], check=True)

        libraries = sorted(
            path
            for path in (root / "usr" / "lib").glob("*.so*")
            if path.is_file() and not path.is_symlink()
        )

        demanded = {}
        results = []
        failures = 0
        for library in libraries:
            imports = glibc_imports(library)
            if imports is None:
                continue
            loaded, stubs, error = load(driver, library, root)
            for name in imports:
                demanded.setdefault(name, set()).add(library.name)
            results.append((library.name, loaded, imports, stubs, error))
            if not loaded:
                failures += 1

    stubbed = {}
    for name, loaded, imports, stubs, error in results:
        for symbol in stubs:
            stubbed.setdefault(symbol, set()).add(name)

    lines = []
    lines.append(f"corpus: {len(results)} libraries, {len(results) - failures} loaded")
    for name, loaded, imports, stubs, error in results:
        if not loaded:
            lines.append(f"  FAIL {name}: {error}")
        elif stubs:
            lines.append(f"  ok   {name}: {len(imports)} glibc imports, {len(stubs)} through stubs")
        else:
            lines.append(f"  ok   {name}: {len(imports)} glibc imports")
    native = sum(1 for symbol in demanded if symbol not in stubbed)
    lines.append(
        f"glibc ABI demand: {len(demanded)} unique symbols, "
        f"{native} satisfied natively, {len(stubbed)} through stubs"
    )
    if stubbed:
        lines.append("stub-resolved (would abort or fault if used):")
        for symbol in sorted(stubbed):
            users = ", ".join(sorted(stubbed[symbol]))
            lines.append(f"  {symbol}  ({users})")
    unknown = sorted(symbol for symbol in demanded if symbol not in inventory)
    if unknown:
        lines.append("demanded but absent from the inventory:")
        for symbol in unknown:
            lines.append(f"  {symbol}")

    report = "\n".join(lines) + "\n"
    print(report, end="")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    trace = ["TN:", "SF:lib/glibc_symbols.json"]
    for symbol, line in sorted(inventory.items(), key=lambda item: item[1]):
        if symbol not in demanded:
            continue
        trace.append(f"DA:{line},{0 if symbol in stubbed else 1}")
    trace.append("end_of_record")
    lcov_path.write_text("\n".join(trace) + "\n")

    if failures:
        raise SystemExit(f"corpus: {failures} library(ies) failed to load")


if __name__ == "__main__":
    main()
