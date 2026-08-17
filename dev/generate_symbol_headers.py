#!/usr/bin/env python3
"""Turn the checked-in symbol tables into the headers the bridge compiles."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def quote(value: str) -> str:
    return json.dumps(value)


def load(path: Path) -> dict:
    table = json.loads(path.read_text())
    source = table["source"]
    symbols = table["symbols"]

    if not symbols:
        raise SystemExit(f"{path}: no symbols")

    return {"source": source, "symbols": symbols}


def musl_header(table: dict) -> list[str]:
    symbols = table["symbols"]
    lines = [
        f"// Generated from musl_symbols.json ({table['source']}).",
        "",
        "// These declarations name the libc the process is linked against, so they",
        "// have to stay at file scope: a C declaration inside an unnamed namespace",
        "// is an internal-linkage object of that namespace for GCC.",
        'extern "C" {',
    ]
    lines += [f"    extern void* {symbol};" for symbol in symbols]
    lines += [
        "}",
        "",
        "namespace {",
        "    static const MuslSymbol muslSymbolTable[] = {",
    ]
    lines += [f"        {{{quote(symbol)}, &{symbol}}}," for symbol in symbols]
    lines += [
        "    };",
        "}",
        "",
    ]

    return lines


def glibc_header(table: dict) -> list[str]:
    symbols = table["symbols"]
    lines = [
        f"// Generated from glibc_symbols.json ({table['source']}).",
        "",
    ]
    entries = []

    for index, symbol in enumerate(symbols):
        name = quote(symbol["name"])
        version = quote(symbol["version"])
        kind = symbol["kind"]
        size = symbol["size"] or 1

        if kind == "function":
            lines += [
                f"    [[noreturn]] static void glibcFunctionStub{index}() noexcept {{",
                f"        abortStub({name}, {version});",
                "    }",
            ]
            entries.append(
                f"        {{{name}, {version}, reinterpret_cast<void*>(glibcFunctionStub{index}), nullptr}},"
            )
        elif kind == "object":
            lines.append(
                f"    alignas(max_align_t) static unsigned char glibcObjectStub{index}[{size}] = {{}};"
            )
            entries.append(f"        {{{name}, {version}, glibcObjectStub{index}, nullptr}},")
        elif kind == "tls":
            lines += [
                f"    alignas(max_align_t) static thread_local unsigned char glibcTlsStub{index}[{size}] = {{}};",
                f"    static void* glibcTlsStubAddress{index}() noexcept {{",
                f"        return glibcTlsStub{index};",
                "    }",
            ]
            entries.append(
                f"        {{{name}, {version}, nullptr, glibcTlsStubAddress{index}}},"
            )
        else:
            raise SystemExit(f"unknown symbol kind: {kind}")

    lines += [
        "",
        "    static const GlibcStub glibcStubTable[] = {",
        *entries,
        "    };",
        "",
    ]

    return lines


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("musl", "glibc"):
        raise SystemExit("usage: generate_symbol_headers.py {musl|glibc} INPUT OUTPUT")

    table = load(Path(sys.argv[2]))
    lines = musl_header(table) if sys.argv[1] == "musl" else glibc_header(table)
    output = Path(sys.argv[3])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))
    print(f"generated {len(table['symbols'])} providers in {output}")


if __name__ == "__main__":
    main()
