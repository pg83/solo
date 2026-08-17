#!/usr/bin/env python3
"""Rank the glibc ABI by real-world demand.

Joins the Debian popcon vote counts with the pinned snapshot's package index,
downloads the most-used library packages, scans their dynamic symbol imports,
and reports which demanded glibc symbols the bridge serves natively, which
resolve into abort stubs, and which are absent from the inventory — each
weighted by the votes of the packages demanding it. The output is the
priority queue for extending the bridge.

usage: abi_demand.py POPCON PACKAGES_XZ COUNT CACHE_DIR OUTPUT
"""

import concurrent.futures
import lzma
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tst"))
from corpus import glibc_imports  # noqa: E402

SNAPSHOT = "https://snapshot.debian.org/archive/debian/20260801T022406Z/"
# glibc itself is what the bridge replaces: its own imports are not
# client demand.
GLIBC = {"libc6"}


def parse_packages(path):
    packages = {}
    entry = {}
    with lzma.open(path, "rt", encoding="utf-8", errors="replace") as index:
        for line in index:
            line = line.rstrip("\n")
            if not line:
                if "Package" in entry:
                    packages[entry["Package"]] = entry
                entry = {}
            elif line[0] not in " \t" and ": " in line:
                key, _, value = line.partition(": ")
                if key in ("Package", "Section", "Filename", "SHA256", "Depends"):
                    entry[key] = value
    return packages


def parse_votes(path):
    votes = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        parts = line.split()
        if not line.startswith("#") and len(parts) >= 4 and parts[3].isdigit():
            votes[parts[1]] = int(parts[3])
    return votes


def ranked_libraries(packages, votes):
    libraries = [
        (votes[name], name)
        for name, info in packages.items()
        if info.get("Section") in ("libs", "oldlibs") and name in votes
    ]
    libraries.sort(reverse=True)
    return libraries


def fetch(url, destination):
    for attempt in range(8):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "dlfcn-test/1"})
            ) as response:
                destination.write_bytes(response.read())
            return
        except OSError:
            if attempt == 7:
                raise
            time.sleep(min(2**attempt, 30))


def package_imports(cache, packages, name):
    """Every glibc/GCC-versioned import of the package's shared objects."""
    info = packages[name]
    cached = cache / Path(info["Filename"]).name
    if not cached.exists():
        fetch(SNAPSHOT + info["Filename"], cached)

    imports = set()
    private = False
    with tempfile.TemporaryDirectory(prefix="dlfcn-demand-") as temporary:
        root = Path(temporary)
        data = subprocess.run(
            ["bsdtar", "-xOf", str(cached), "data.tar.*"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        subprocess.run(["bsdtar", "-xpf", "-", "-C", str(root)], input=data, check=True)
        for library in root.rglob("*.so*"):
            if not library.is_file() or library.is_symlink():
                continue
            found = glibc_imports(library)
            if found is None:
                continue
            imports |= found
            private |= any("@GLIBC_PRIVATE" in item for item in found)
    return imports, private


def bridge_coverage():
    """What the bridge serves natively: musl exports plus the adapter table."""
    root = Path(__file__).resolve().parent.parent
    native = set(re.findall(r'"([^"]+)"', (root / "lib/musl_symbols_x86_64.json").read_text()))
    native |= set(re.findall(r'SH_(?:FUNCTION|OBJECT)\("([^"]+)"', (root / "lib/glibc_shim.cpp").read_text()))
    native |= {"stdin", "stdout", "stderr", "_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_", "__libc_single_threaded"}

    inventory = set()
    for line in (root / "lib/glibc_symbols_x86_64.json").read_text().splitlines():
        found = re.match(r'\s*\{"name": "([^"]+)", "version": "([^"]+)"', line)
        if found:
            inventory.add((found.group(1), found.group(2)))
    return native, inventory


def main():
    if len(sys.argv) != 6:
        raise SystemExit(__doc__)

    popcon, packages_xz, count, cache_dir, output = sys.argv[1:]
    packages = parse_packages(packages_xz)
    ranking = [
        (vote, name)
        for vote, name in ranked_libraries(packages, parse_votes(popcon))
        if name not in GLIBC
    ][: int(count)]
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    demand = {}
    weight = {}
    scanned = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(package_imports, cache, packages, name): (vote, name)
            for vote, name in ranking
        }
        for future in concurrent.futures.as_completed(futures):
            vote, name = futures[future]
            imports, _ = future.result()
            scanned += 1
            if scanned % 50 == 0:
                print(f"scanned {scanned}/{len(ranking)}", file=sys.stderr)
            for item in imports:
                demand.setdefault(item, set()).add(name)
                weight[item] = weight.get(item, 0) + vote

    native, inventory = bridge_coverage()
    stubbed = []
    absent = []
    served = 0
    for item, packages_demanding in demand.items():
        name, _, version = item.partition("@")
        if version.startswith(("GCC_", "CXXABI", "GLIBCXX")):
            continue
        if name in native:
            served += 1
        elif (name, version) in inventory:
            stubbed.append((weight[item], item, packages_demanding))
        else:
            absent.append((weight[item], item, packages_demanding))

    lines = [
        f"demand: top {len(ranking)} library packages by popcon vote, "
        f"{len(demand)} unique imports, {served} served natively, "
        f"{len(stubbed)} through stubs, {len(absent)} absent from the inventory",
        "",
        "stub-resolved (would abort or fault if called), by demand weight:",
    ]
    for total, item, names in sorted(stubbed, reverse=True):
        sample = ", ".join(sorted(names)[:4])
        more = f" +{len(names) - 4}" if len(names) > 4 else ""
        lines.append(f"  {total:9d}  {item}  ({sample}{more})")
    lines.append("")
    lines.append("absent from the inventory (load would fail), by demand weight:")
    for total, item, names in sorted(absent, reverse=True):
        sample = ", ".join(sorted(names)[:4])
        more = f" +{len(names) - 4}" if len(names) > 4 else ""
        lines.append(f"  {total:9d}  {item}  ({sample}{more})")

    Path(output).write_text("\n".join(lines) + "\n")
    print(f"wrote {output}: {len(stubbed)} stubbed, {len(absent)} absent", file=sys.stderr)


if __name__ == "__main__":
    main()
