#!/usr/bin/env python3

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path.cwd()
SOURCE_PATTERNS = ("*.cpp", "*.h", "*.hpp", "*.mm")
EXCLUDED_DIRS = {"third_party", "ext"}
# Vendored trees keep their upstream formatting.
VENDORED_ROOTS = (
    ROOT / "bin" / "vulkan" / "llvm",
    ROOT / "bin" / "vulkan" / "musl",
    ROOT / "bin" / "vulkan" / "png",
    ROOT / "bin" / "vulkan" / "vulkan",
    ROOT / "bin" / "vulkan" / "zlib",
)
INITIALIZER_LIST = re.compile(r"^(?P<indent> +):(?=\s)")
INCLUDE = re.compile(r'^#include\s+(?P<open>["<])(?P<path>[^">]+)[">]\s*(?P<tail>//.*)?$')
RAW_STRING = re.compile(r'(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\(')


def vendored(path):
    return any(path.is_relative_to(root) for root in VENDORED_ROOTS)


def source_files(arguments):
    if arguments:
        return [Path(argument).resolve() for argument in arguments]

    output = subprocess.check_output(
        ["git", "ls-files", "-z", "--", *SOURCE_PATTERNS], cwd=ROOT
    )
    return [
        path
        for name in output.decode().split("\0")
        if name and not vendored(path := ROOT / name)
    ]


def format_sources(files):
    command = shlex.split(os.environ.get("CLANG_FORMAT", "clang-format"))
    subprocess.run(
        [*command, "-i", "--style=file", *map(str, files)],
        cwd=ROOT,
        check=True,
    )


def restore_constructor_braces(path):
    lines = path.read_text().splitlines(keepends=True)
    changed = False
    in_initializers = False
    body_indent = ""
    parens = 0
    brackets = 0
    braces = 0
    quote = None
    escaped = False
    block_comment = False

    for line_number, line in enumerate(lines):
        if not in_initializers:
            match = INITIALIZER_LIST.match(line)
            if match is None:
                continue

            indent = match.group("indent")
            previous_number = line_number - 1
            while previous_number >= 0 and not lines[previous_number].strip():
                previous_number -= 1
            if previous_number < 0:
                continue
            previous = lines[previous_number]
            previous_indent = len(previous) - len(previous.lstrip(" "))
            if previous_indent + 4 != len(indent) or not previous.rstrip().endswith(")"):
                continue
            body_indent = indent[:-4] if indent.endswith("    ") else ""
            in_initializers = True
            parens = brackets = braces = 0
            quote = None
            escaped = False
            block_comment = False

        column = 0
        while column < len(line):
            char = line[column]
            following = line[column + 1] if column + 1 < len(line) else ""

            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    column += 2
                    continue
                column += 1
                continue

            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                column += 1
                continue

            if char == "/" and following == "/":
                break
            if char == "/" and following == "*":
                block_comment = True
                column += 2
                continue
            if char == '"' or char == "'":
                quote = char
                column += 1
                continue

            if char == "(":
                parens += 1
            elif char == ")":
                parens -= 1
            elif char == "[":
                brackets += 1
            elif char == "]":
                brackets -= 1
            elif char == "{":
                previous = line[:column].rstrip()
                is_body = (
                    parens == 0
                    and brackets == 0
                    and braces == 0
                    and previous.endswith(")")
                    and not line[column + 1 :].strip()
                )
                if is_body:
                    newline = "\r\n" if line.endswith("\r\n") else "\n"
                    lines[line_number] = (
                        previous + newline + body_indent + "{" + newline
                    )
                    in_initializers = False
                    changed = True
                    break
                braces += 1
            elif char == "}":
                braces -= 1

            column += 1

    if changed:
        path.write_text("".join(lines))


def strip_brace_boundary_blank_lines(path):
    lines = path.read_text().splitlines(keepends=True)
    code_lines = []
    block_comment = False
    quote = None
    raw_close = None

    for line in lines:
        code = []
        column = 0
        while column < len(line):
            if raw_close is not None:
                closing = line.find(raw_close, column)
                if closing == -1:
                    column = len(line)
                else:
                    column = closing + len(raw_close)
                    raw_close = None
                continue

            if block_comment:
                closing = line.find("*/", column)
                if closing == -1:
                    column = len(line)
                else:
                    column = closing + 2
                    block_comment = False
                continue

            if quote is not None:
                char = line[column]
                if char == "\\":
                    column += 2
                elif char == quote:
                    quote = None
                    column += 1
                else:
                    column += 1
                continue

            if line.startswith("//", column):
                break
            if line.startswith("/*", column):
                block_comment = True
                column += 2
                continue

            raw_match = RAW_STRING.match(line, column)
            if raw_match is not None and (
                column == 0 or not (line[column - 1].isalnum() or line[column - 1] == "_")
            ):
                raw_close = ")" + raw_match.group("delimiter") + '"'
                column = raw_match.end()
                continue

            char = line[column]
            if char in ('"', "'"):
                quote = char
                column += 1
                continue
            code.append(char)
            column += 1

        if quote is not None and line.endswith(("\n", "\r")):
            content = line.rstrip("\r\n")
            backslashes = len(content) - len(content.rstrip("\\"))
            if backslashes % 2 == 0:
                quote = None
        code_lines.append("".join(code))

    keep = [True] * len(lines)
    line_number = 0
    while line_number < len(lines):
        if lines[line_number].strip(" \t\r\n"):
            line_number += 1
            continue
        end = line_number + 1
        while end < len(lines) and not lines[end].strip(" \t\r\n"):
            end += 1
        after_open = line_number > 0 and code_lines[line_number - 1].rstrip().endswith("{")
        before_close = end < len(lines) and code_lines[end].lstrip().startswith("}")
        if after_open or before_close:
            for blank in range(line_number, end):
                keep[blank] = False
        line_number = end

    replacement = "".join(line for line, retain in zip(lines, keep) if retain)
    if replacement != "".join(lines):
        path.write_text(replacement)


def reorder_includes(path):
    """Rewrite the leading include block into the canonical order: the
    paired header, project headers, <std/...>, then everything else — least
    general to most general, each group sorted, one blank line between
    groups. Only the unconditional run at the top of the file is touched;
    the first comment, conditional or code line ends it, so #ifdef'd
    includes and order-sensitive tails stay where they are."""
    text = path.read_text()
    lines = text.splitlines(keepends=True)

    pragma = []
    includes = []
    preamble = []
    end = 0
    in_comment = False
    for line_number, line in enumerate(lines):
        stripped = line.strip()
        if not includes and (in_comment or stripped.startswith("/*")):
            # The license header (and any other leading comment) sits
            # above the include run; keep it in place verbatim.
            preamble.append(line)
            if in_comment:
                in_comment = not stripped.endswith("*/")
            else:
                in_comment = not (stripped.endswith("*/") and len(stripped) > 3)
            end = line_number + 1
            continue
        if not stripped:
            end = line_number + 1
            continue
        if stripped == "#pragma once" and not includes:
            pragma.append(line)
            end = line_number + 1
            continue
        match = INCLUDE.match(stripped)
        if match is None:
            break
        includes.append((match.group("open"), match.group("path"), line))
        end = line_number + 1

    if not includes:
        return

    paired = path.stem + ".h"
    groups = ([], [], [], [], [])
    for open_char, include_path, line in includes:
        if open_char == '"' and include_path == paired and path.suffix != ".h":
            group = 0
        elif open_char == '"':
            group = 1
        elif include_path.startswith("lib/"):
            # Cross-library project headers by full path, e.g.
            # <lib/vterm/...>: still project code, ahead of libstd.
            group = 2
        elif include_path.startswith("std/"):
            group = 3
        else:
            group = 4
        groups[group].append((include_path, line.rstrip("\n").rstrip("\r")))

    newline = "\r\n" if lines[0].endswith("\r\n") else "\n"
    block = "".join(preamble)
    if preamble:
        block += newline
    block += "".join(pragma)
    if pragma:
        block += newline
    parts = []
    for group in groups:
        if group:
            ordered = sorted(group, key=lambda entry: (len(entry[0]), entry[0]))
            parts.append(newline.join(line for _, line in ordered) + newline)
    block += newline.join(parts)

    rest = "".join(lines[end:])
    replacement = block + newline + rest if rest.strip() else block
    if replacement != text:
        path.write_text(replacement)


def main():
    command = shlex.split(os.environ.get("CLANG_FORMAT", "clang-format"))
    if shutil.which(command[0]) is None:
        raise SystemExit(f"style.py: {command[0]} not found; nothing was touched")

    files = [
        path
        for path in source_files(sys.argv[1:])
        if not EXCLUDED_DIRS.intersection(path.parts)
    ]
    if not files:
        return

    for path in files:
        reorder_includes(path)
    format_sources(files)
    for path in files:
        restore_constructor_braces(path)
        strip_brace_boundary_blank_lines(path)


if __name__ == "__main__":
    main()
