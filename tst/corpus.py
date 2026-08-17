#!/usr/bin/env python3
"""Load corpus libraries through SoLo and report glibc ABI coverage.

`load` handles one package: the package's own libraries are loaded eagerly in
a fresh process each, with the declared dependency packages extracted next to
them, and the per-library results land in a JSON file. Imports that resolve
into abort or inaccessible-object stubs are collected from the bridge's debug
output.

`report` merges the per-package results into a text report and an lcov trace
mapped onto the lines of the platform's glibc symbol inventory, so the
coverage service shows which ABI entries the corpus demands and which of them
only have stubs.
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

STUB_LINE = "glibc bridge: resolved fallback "
OBJECT_LINE = "glibc bridge: unimplemented data object "

SHT_DYNAMIC = 6
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


def members(package):
    """The archive's file list; a .deb nests it inside data.tar."""
    if package.endswith(".deb"):
        data = subprocess.run(
            ["bsdtar", "-xOf", package, "data.tar.*"], check=True, stdout=subprocess.PIPE
        ).stdout
        listing = subprocess.run(
            ["bsdtar", "-tf", "-"], input=data, check=True, stdout=subprocess.PIPE
        ).stdout
        return listing.decode().splitlines()
    return subprocess.run(
        ["bsdtar", "-tf", package], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.splitlines()


def extract(package, root):
    if package.endswith(".deb"):
        data = subprocess.run(
            ["bsdtar", "-xOf", package, "data.tar.*"], check=True, stdout=subprocess.PIPE
        ).stdout
        subprocess.run(["bsdtar", "-xpf", "-", "-C", str(root)], input=data, check=True)
    else:
        subprocess.run(["bsdtar", "-xpf", package, "-C", str(root)], check=True)


def elf_dynamic(path):
    """The library's soname and DT_NEEDED entries."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None, []
    table = sections(data)
    dynamic = next((s for s in table if s["type"] == SHT_DYNAMIC), None)
    if dynamic is None:
        return None, []
    strings = table[dynamic["link"]]
    soname = None
    needed = []
    for offset in range(dynamic["offset"], dynamic["offset"] + dynamic["size"], 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == 0:
            break
        if tag in (1, 14):
            end = data.index(b"\0", strings["offset"] + value)
            name = data[strings["offset"] + value : end].decode()
            if tag == 1:
                needed.append(name)
            else:
                soname = name
    return soname, needed


def library_directories(root):
    """Every extracted directory holding a shared object: the union of what
    RPATH entries and ld.so.conf.d snippets would cover on a real system,
    where our extraction root's absolute paths cannot."""
    directories = []
    for path, _, files in os.walk(root):
        if any(".so" in name for name in files):
            directories.append(path)
    return sorted(directories)


def needs_host_symbols(error):
    """A plugin importing unversioned symbols of its host application cannot
    be loaded standalone under any loader; that is the plugin's contract, not
    a bridge defect. A missing @GLIBC symbol never matches here."""
    return re.search(r"(?:unresolved symbol|no ABI thunk for) [^\s@]+$", error) is not None


def run_driver(driver, library, search_path):
    environment = os.environ.copy()
    environment["DL_GLIBC_STUB_DEBUG"] = "1"
    environment.pop("DL_ELF_LIBRARY_PATH", None)
    environment["LD_LIBRARY_PATH"] = search_path
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


def load(arguments):
    if len(arguments) < 3:
        raise SystemExit("usage: corpus.py load RESULT DRIVER PACKAGE [DEPENDENCY...]")

    result_path = Path(arguments[0])
    driver = arguments[1]
    package = arguments[2]
    dependencies = arguments[3:]

    results = {}
    failures = 0
    with tempfile.TemporaryDirectory(prefix="dlfcn-corpus-") as temporary:
        root = Path(temporary)
        for archive in [package, *dependencies]:
            extract(archive, root)

        search_path = os.pathsep.join(library_directories(root))
        for member in sorted(members(package)):
            library = root / member
            # Only the top-level libraries and the packages' plugin modules;
            # language bindings under site-packages need their interpreter.
            if "site-packages" in member or "/lib/security/" in member:
                continue
            if "/lib/" not in member or ".so" not in member:
                continue
            if not library.is_file() or library.is_symlink():
                continue
            imports = glibc_imports(library)
            if imports is None:
                continue
            loaded, stubs, error = run_driver(driver, library, search_path)
            skipped = not loaded and error is not None and needs_host_symbols(error)
            results[library.name] = {
                "loaded": loaded,
                "skipped": skipped,
                "imports": sorted(imports),
                "stubs": sorted(stubs),
                "error": error,
            }
            if skipped:
                print(f"skip {library.name}: {error}", file=sys.stderr)
            elif not loaded:
                failures += 1
                print(f"FAIL {library.name}: {error}", file=sys.stderr)

    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")

    if failures:
        raise SystemExit(f"corpus: {failures} library(ies) failed to load")


def report(arguments):
    if len(arguments) < 4:
        raise SystemExit("usage: corpus.py report REPORT LCOV SYMBOLS_JSON RESULT...")

    report_path = Path(arguments[0])
    lcov_path = Path(arguments[1])
    symbols_path = Path(arguments[2])
    inventory = {}
    for number, line in enumerate(symbols_path.read_text().splitlines(), 1):
        line = line.strip().rstrip(",")
        if line.startswith('{"name"'):
            entry = json.loads(line)
            inventory[f"{entry['name']}@{entry['version']}"] = number

    results = {}
    for result in arguments[3:]:
        results.update(json.loads(Path(result).read_text()))

    demanded = {}
    stubbed = {}
    for name, library in sorted(results.items()):
        for symbol in library["imports"]:
            demanded.setdefault(symbol, set()).add(name)
        for symbol in library["stubs"]:
            stubbed.setdefault(symbol, set()).add(name)

    skipped = sum(1 for library in results.values() if library.get("skipped"))
    lines = [f"corpus: {len(results)} libraries, {skipped} host plugins skipped"]
    for name, library in sorted(results.items()):
        if library.get("skipped"):
            lines.append(f"  skip {name}: needs its host application's symbols")
            continue
        stubs = f", {len(library['stubs'])} through stubs" if library["stubs"] else ""
        lines.append(f"  ok   {name}: {len(library['imports'])} glibc imports{stubs}")
    native = sum(1 for symbol in demanded if symbol not in stubbed)
    lines.append(
        f"glibc ABI demand: {len(demanded)} unique symbols, "
        f"{native} satisfied natively, {len(stubbed)} through stubs"
    )
    if stubbed:
        lines.append("stub-resolved (would abort or fault if used):")
        for symbol in sorted(stubbed):
            lines.append(f"  {symbol}  ({', '.join(sorted(stubbed[symbol]))})")
    unknown = sorted(symbol for symbol in demanded if symbol not in inventory)
    if unknown:
        lines.append("demanded but absent from the inventory:")
        lines += [f"  {symbol}" for symbol in unknown]

    text = "\n".join(lines) + "\n"
    print(text, end="")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(text)

    trace = ["TN:", f"SF:lib/{symbols_path.name}"]
    for symbol, line in sorted(inventory.items(), key=lambda item: item[1]):
        if symbol in demanded:
            trace.append(f"DA:{line},{0 if symbol in stubbed else 1}")
    trace.append("end_of_record")
    lcov_path.write_text("\n".join(trace) + "\n")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("load", "report"):
        raise SystemExit("usage: corpus.py {load|report} ...")

    if sys.argv[1] == "load":
        load(sys.argv[2:])
    else:
        report(sys.argv[2:])


if __name__ == "__main__":
    main()
