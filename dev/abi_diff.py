#!/usr/bin/env python3
"""Diff the glibc and musl ABI as seen through dev/abi_probe.c.

The probe is compiled to an object file twice — against the extracted headers
of the pinned Arch glibc (plus the Linux API headers) and against the vendored
musl headers — and never linked or run: every probed number is encoded in the
size of a symbol, read back here. The output table marks every probe as
matching, differing, or present on one side only; the differing rows are the
shim work list.
"""

import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

OFFSET_BIAS = 1
VALUE_BIAS = 4096

SHT_SYMTAB = 2


def builtin_include(compiler):
    """The compiler's own header directory (stddef.h and friends)."""
    candidates = []
    for flags in (["-print-file-name=include"], ["-print-resource-dir"]):
        result = subprocess.run(
            [*compiler, *flags], text=True, stdout=subprocess.PIPE, check=False
        )
        path = Path(result.stdout.strip())
        if flags == ["-print-resource-dir"]:
            path = path / "include"
        if result.returncode == 0:
            candidates.append(path)

    listing = subprocess.run(
        [*compiler, "-E", "-v", "-xc", "-"],
        input="",
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    ).stderr.splitlines()
    candidates += [Path(line.strip()) for line in listing if line.startswith(" /")]

    binary = shutil.which(compiler[0])
    if binary:
        prefix = Path(binary).resolve().parent.parent
        candidates.append(prefix / "share" / "include")
        candidates += sorted(prefix.glob("lib/clang/*/include"))

    for path in candidates:
        if path.is_absolute() and (path / "stddef.h").is_file():
            return path
    raise SystemExit(f"abi_diff.py: cannot find the builtin headers of {compiler}")


def compile_probe(compiler, probe, output, includes):
    subprocess.run(
        [
            *compiler,
            "-c",
            "-o",
            str(output),
            "-nostdinc",
            *[flag for path in includes for flag in ("-isystem", str(path))],
            "-D_GNU_SOURCE",
            str(probe),
        ],
        check=True,
    )


def probe_symbols(path):
    data = path.read_bytes()
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    table = []
    for index in range(shnum):
        raw = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        table.append({"type": raw[1], "offset": raw[4], "size": raw[5], "link": raw[6], "entsize": raw[9]})
    symtab = next(s for s in table if s["type"] == SHT_SYMTAB)
    strings = table[symtab["link"]]

    values = {}
    for index in range(1, symtab["size"] // symtab["entsize"]):
        name, _, _, _, _, size = struct.unpack_from("<IBBHQQ", data, symtab["offset"] + index * symtab["entsize"])
        end = data.index(b"\0", strings["offset"] + name)
        symbol = data[strings["offset"] + name : end].decode()
        if not symbol.startswith("probe_"):
            continue
        kind, tag = symbol[len("probe_") :].split("_", 1)
        if kind == "offset":
            size -= OFFSET_BIAS
        elif kind == "value":
            size -= VALUE_BIAS
        values[f"{kind} {tag}"] = size
    return values


def main():
    if len(sys.argv) != 7:
        raise SystemExit(
            "usage: abi_diff.py OUTPUT CC PROBE GLIBC_PKG KERNEL_PKG MUSL_INCLUDES"
        )

    output = Path(sys.argv[1])
    compiler = shlex.split(sys.argv[2])
    probe = Path(sys.argv[3])
    glibc_package = sys.argv[4]
    kernel_package = sys.argv[5]
    musl_includes = [Path(part) for part in sys.argv[6].split(":")]
    builtin = builtin_include(compiler)

    with tempfile.TemporaryDirectory(prefix="dlfcn-abi-") as temporary:
        root = Path(temporary)
        for archive in (glibc_package, kernel_package):
            subprocess.run(["bsdtar", "-xpf", archive, "-C", str(root)], check=True)

        glibc_object = root / "glibc.o"
        musl_object = root / "musl.o"
        compile_probe(compiler, probe, glibc_object, [root / "usr" / "include", builtin])
        compile_probe(compiler, probe, musl_object, [*musl_includes, builtin])

        glibc = probe_symbols(glibc_object)
        musl = probe_symbols(musl_object)

    rows = []
    for name in sorted(glibc.keys() | musl.keys()):
        left = glibc.get(name)
        right = musl.get(name)
        if left == right:
            state = "ok"
        elif left is None:
            state = "musl-only"
        elif right is None:
            state = "glibc-only"
        else:
            state = "DIFF"
        rows.append((state, name, left, right))

    def fmt(value):
        return "-" if value is None else str(value)

    lines = []
    counts = {}
    for state, name, left, right in rows:
        counts[state] = counts.get(state, 0) + 1
    lines.append(
        "abi probe: "
        + ", ".join(f"{counts.get(state, 0)} {state}" for state in ("ok", "DIFF", "glibc-only", "musl-only"))
    )
    lines.append(f"{'':10} {'probe':44} {'glibc':>12} {'musl':>12}")
    for wanted in ("DIFF", "glibc-only", "musl-only", "ok"):
        for state, name, left, right in rows:
            if state == wanted:
                lines.append(f"{state:10} {name:44} {fmt(left):>12} {fmt(right):>12}")

    text = "\n".join(lines) + "\n"
    print("\n".join(lines[: 2 + counts.get('DIFF', 0) + counts.get('glibc-only', 0) + counts.get('musl-only', 0)]))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)


if __name__ == "__main__":
    main()
