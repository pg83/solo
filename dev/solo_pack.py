#!/usr/bin/env python3

"""Append a program and its libraries to a solo stub, making one file.

The stub is an ordinary static executable that links solo's loader and calls
soloBundleMain(). Everything this tool appends to it is found at runtime
through the stub's own /proc/self/exe: a trailer at the very end of the file
points at an index, and the index names members that start on 64 KiB
boundaries, so the loader maps them straight out of the file rather than
unpacking them anywhere.

Members are matched by name against what the guest asks for, so a library is
registered under its SONAME as well as its file name; a name the bundle does
not carry is looked up on the host as usual, which is how a bundled program
still uses the machine's own GPU driver.

    solo-pack --stub ./stub --program ./chrome \\
              --library ./libwayland-client.so.0 --output ./chrome.bundle
"""

import argparse
import os
import struct
import sys

MAGIC = b"SOLOBNDL"
VERSION = 1
# 64 KiB satisfies every Linux page size in use, so a bundle built on a 4 KiB
# host still maps on a 64 KiB-page kernel.
ALIGNMENT = 64 * 1024
ENTRY_EXECUTABLE = 1

TRAILER = struct.Struct("<8sIIQQ")
ENTRY = struct.Struct("<QQII")


def dynamic(path):
    """The DT_SONAME and DT_NEEDED names of an ELF, as (soname, needed).

    Read through the program headers rather than the section table: a
    stripped library keeps the former and may well have lost the latter.
    Anything that is not a 64-bit little-endian ELF reads as empty.
    """
    with open(path, "rb") as handle:
        data = handle.read()

    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None, []

    e_phoff, = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)

    loads = []
    section = None

    for index in range(e_phnum):
        header = e_phoff + index * e_phentsize
        p_type, = struct.unpack_from("<I", data, header)
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, header + 8)
        p_filesz, = struct.unpack_from("<Q", data, header + 32)

        if p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_filesz, p_offset))
        elif p_type == 2:  # PT_DYNAMIC
            section = (p_offset, p_filesz)

    if section is None:
        return None, []

    def offsetOf(address):
        for p_vaddr, p_filesz, p_offset in loads:
            if p_vaddr <= address < p_vaddr + p_filesz:
                return p_offset + (address - p_vaddr)
        return None

    strtab = None
    own = None
    wanted = []
    cursor, size = section

    for position in range(cursor, cursor + size, 16):
        tag, value = struct.unpack_from("<QQ", data, position)

        if tag == 0:  # DT_NULL
            break
        if tag == 5:  # DT_STRTAB
            strtab = offsetOf(value)
        elif tag == 14:  # DT_SONAME
            own = value
        elif tag == 1:  # DT_NEEDED
            wanted.append(value)

    if strtab is None:
        return None, []

    def name(offset):
        end = data.index(b"\0", strtab + offset)

        return data[strtab + offset:end].decode()

    return (name(own) if own is not None else None), [name(offset) for offset in wanted]


class Member:
    def __init__(self, path, names, executable):
        self.path = path
        self.names = names
        self.executable = executable
        self.offset = 0
        self.size = os.path.getsize(path)


def memberFor(specification, executable):
    """A --program/--library argument: PATH, or NAME=PATH to override the
    names the member answers to (comma-separated)."""
    if "=" in specification:
        names, _, path = specification.partition("=")
        names = [name for name in names.split(",") if name]
    else:
        path = specification
        names = []

    if not names:
        names = [os.path.basename(path)]

        if not executable:
            embedded, _ = dynamic(path)

            if embedded and embedded not in names:
                names.append(embedded)

    return Member(path, names, executable)


def build(stub, members, output):
    with open(stub, "rb") as handle:
        blob = bytearray(handle.read())

    for member in members:
        padding = -len(blob) % ALIGNMENT

        blob.extend(b"\0" * padding)
        member.offset = len(blob)

        with open(member.path, "rb") as handle:
            blob.extend(handle.read())

    # Entries first, then the names they point into, all in one block: the
    # loader reads it whole and validates that every name offset lands in it.
    entries = [(member, name) for member in members for name in member.names]
    names = bytearray()
    offsets = {}
    header = len(entries) * ENTRY.size

    for _, name in entries:
        if name not in offsets:
            offsets[name] = header + len(names)
            names.extend(name.encode() + b"\0")

    index = bytearray()

    for member, name in entries:
        index.extend(ENTRY.pack(
            member.offset,
            member.size,
            offsets[name],
            ENTRY_EXECUTABLE if member.executable else 0,
        ))

    index.extend(names)

    indexOffset = len(blob)

    blob.extend(index)
    blob.extend(TRAILER.pack(MAGIC, VERSION, len(entries), indexOffset, len(index)))

    with open(output, "wb") as handle:
        handle.write(blob)

    os.chmod(output, 0o755)

    return entries


def listBundle(path):
    with open(path, "rb") as handle:
        blob = handle.read()

    if len(blob) < TRAILER.size:
        raise SystemExit(f"{path}: too small to carry a bundle")

    magic, version, count, indexOffset, indexSize = TRAILER.unpack(blob[-TRAILER.size:])

    if magic != MAGIC:
        raise SystemExit(f"{path}: no bundle here")
    if version != VERSION:
        raise SystemExit(f"{path}: bundle version {version}, this tool speaks {VERSION}")

    index = blob[indexOffset:indexOffset + indexSize]

    print(f"{path}: {count} entries, index at {indexOffset}")

    for position in range(count):
        offset, size, nameOffset, flags = ENTRY.unpack_from(index, position * ENTRY.size)
        end = index.index(b"\0", nameOffset)
        name = index[nameOffset:end].decode()
        kind = "program" if flags & ENTRY_EXECUTABLE else "library"

        print(f"  {kind:8} {name:40} offset={offset} size={size}")


def check(members):
    """Names the guest closure asks for that the bundle does not carry.

    Whatever this reports comes from the host at runtime, or from a static
    provider linked into the stub. Reading the list is how the set of
    libraries a stub has to provide gets assembled.
    """
    carried = {name for member in members for name in member.names}
    wanted = []

    for member in members:
        for name in dynamic(member.path)[1]:
            if name not in carried and name not in wanted:
                wanted.append(name)

    return wanted


def main():
    parser = argparse.ArgumentParser(description="append a program and its libraries to a solo stub")
    parser.add_argument("--stub", help="the stub executable to append to")
    parser.add_argument("--program", help="the guest to run, as PATH or NAME=PATH")
    parser.add_argument("--library", action="append", default=[], metavar="SPEC",
                        help="a library the bundle carries, as PATH or NAME[,NAME...]=PATH")
    parser.add_argument("--output", help="the bundle to write")
    parser.add_argument("--list", metavar="BUNDLE", help="print an existing bundle's members and exit")
    parser.add_argument("--check", action="store_true",
                        help="also report the names the bundle does not carry")
    arguments = parser.parse_args()

    if arguments.list:
        listBundle(arguments.list)

        return 0

    for required in ("stub", "program", "output"):
        if not getattr(arguments, required):
            parser.error(f"--{required} is required")

    members = [memberFor(arguments.program, True)]
    members.extend(memberFor(specification, False) for specification in arguments.library)

    entries = build(arguments.stub, members, arguments.output)

    print(f"{arguments.output}: {len(members)} members, {len(entries)} names, {os.path.getsize(arguments.output)} bytes")

    if arguments.check:
        for name in check(members):
            print(f"  from the host or a provider: {name}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
