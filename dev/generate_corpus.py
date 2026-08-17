#!/usr/bin/env python3
"""Generate the corpus package tables from popcon popularity.

The load set is the most-used library packages by Debian popcon vote, plus
the keep list (regression anchors like jemalloc). Each package's dependency
list is the union of two closures: the package index's Depends fields,
restricted to library packages, and the DT_NEEDED sonames of its shared
objects resolved through a soname-to-package map built from the same scan —
plugins routinely need libraries their package only Suggests. glibc itself
and its runtime sonames are the bridge's job and stay out. Packages whose
shared objects import GLIBC_PRIVATE are glibc-internal and ride along as
dependencies at most; packages without any glibc-importing shared object are
not worth a load node. The output is one JSON table per architecture, which
build.py turns into download and load nodes.

usage: generate_corpus.py POPCON PACKAGES_XZ_AMD64 PACKAGES_XZ_ARM64 COUNT CACHE_DIR OUTPUT_DIR

The PACKAGES_XZ arguments take comma-separated index files. The first is the
ranking universe (main); the rest (non-free) only contribute packages the
keep list names and the closures they pull in.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tst"))
from abi_demand import GLIBC, SNAPSHOT, fetch, parse_packages, parse_votes, ranked_libraries  # noqa: E402
from corpus import elf_dynamic, glibc_imports  # noqa: E402

CONTENTS = SNAPSHOT + "dists/sid/main/Contents-amd64.gz"

KEEP = [
    "libjemalloc2",
    "openssl-provider-legacy",
    # The NVIDIA userspace blobs, the field-reported demand source: their
    # imports (the pre-2.33 stat family, dlmopen, mallinfo) must stay
    # served. The ICD packages ship only manifests; these carry the code.
    "libcuda1",
    "libglx-nvidia0",
    "libnvidia-eglcore",
    "libnvidia-glcore",
    "libnvidia-gpucomp",
    "libnvidia-ml1",
]
# Environment-gated runtimes whose constructors abort by design on ordinary
# kernels; they would fail under ld.so on the same machine.
SKIP = {
    "libasan8": "sanitizer runtimes must come first in the process",
    "libtsan2": "sanitizer runtimes must come first in the process",
    "libhwasan0": "requires the kernel's tagged address ABI",
    "liblsan0": "56 KiB of initial-exec TLS, beyond any dlopen-time surplus",
}
BRIDGED_SONAMES = {
    "libc.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "libm.so.6",
    "librt.so.1",
    "libresolv.so.2",
    "libmvec.so.1",
    "libutil.so.1",
    "libanl.so.1",
    "libnsl.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
}


def contents_providers(cache):
    """The soname-to-package map of the whole snapshot, from the Contents
    index: the fallback when neither popularity nor Depends brought the
    provider into the scanned universe."""
    import gzip

    cached = cache / "Contents-amd64.gz"
    if not cached.exists():
        fetch(CONTENTS, cached)

    providers = {}
    with gzip.open(cached, "rt", encoding="utf-8", errors="replace") as contents:
        for line in contents:
            path, _, package = line.rpartition(" ")
            path = path.rstrip()
            # Only the native library tree: private copies elsewhere
            # (usr/lib32, gcc-snapshot) must not become providers.
            if not path.startswith(("usr/lib/x86_64-linux-gnu/", "usr/lib/lib")):
                continue
            basename = path.rsplit("/", 1)[-1]
            # Only versioned runtime names; the bare .so links belong to the
            # -dev packages.
            if not re.match(r"lib[^/]*\.so\.", basename):
                continue
            providers.setdefault(basename, package.strip().rpartition("/")[2])
    return providers


def dependency_names(info):
    names = []
    for clause in info.get("Depends", "").split(","):
        alternative = clause.split("|")[0].strip()
        if alternative:
            names.append(re.split(r"[\s:(]", alternative)[0])
    return names


class Profiles:
    """Per-package facts scraped from the cached .deb: whether its shared
    objects import glibc symbols, whether any import is GLIBC_PRIVATE, the
    sonames it provides, and the sonames its objects need."""

    def __init__(self, cache, packages):
        self.cache = cache
        self.packages = packages
        self.known = {}

    def of(self, name):
        if name in self.known:
            return self.known[name]

        info = self.packages[name]
        cached = self.cache / Path(info["Filename"]).name
        if not cached.exists():
            fetch(SNAPSHOT + info["Filename"], cached)

        imports = False
        private = False
        provides = set()
        needs = set()
        with tempfile.TemporaryDirectory(prefix="dlfcn-corpus-gen-") as temporary:
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
                imports |= bool(found)
                private |= any("@GLIBC_PRIVATE" in item for item in found)
                soname, needed = elf_dynamic(library)
                provides.add(soname if soname else library.name)
                needs |= set(needed)

        self.known[name] = (imports, private, provides, needs)
        return self.known[name]


def main():
    if len(sys.argv) != 7:
        raise SystemExit(__doc__)

    popcon, amd64_xz, arm64_xz, count, cache_dir, output_dir = sys.argv[1:]
    amd64_indexes = [parse_packages(path) for path in amd64_xz.split(",")]
    arm64_indexes = [parse_packages(path) for path in arm64_xz.split(",")]
    amd64 = {}
    for index in amd64_indexes:
        amd64.update(index)
    arm64 = {}
    for index in arm64_indexes:
        arm64.update(index)
    votes = parse_votes(popcon)
    profiles = Profiles(Path(cache_dir), amd64)

    candidates = [name for _, name in ranked_libraries(amd64_indexes[0], votes)[: int(count)]]
    candidates += [name for name in KEEP if name in amd64 and name not in candidates]

    # Only packages with glibc-importing shared objects earn a load node,
    # and GLIBC_PRIVATE importers are glibc-internal: dependencies at most.
    load = []
    for index, name in enumerate(candidates, 1):
        if name in GLIBC:
            continue
        if name in SKIP:
            print(f"skipped, {SKIP[name]}: {name}", file=sys.stderr)
            continue
        imports, private, _, _ = profiles.of(name)
        if index % 100 == 0:
            print(f"classified {index}/{len(candidates)}", file=sys.stderr)
        if private:
            print(f"GLIBC_PRIVATE, dependency only: {name}", file=sys.stderr)
        elif imports:
            load.append(name)

    def library_package(name, packages, providing):
        if name in GLIBC or name not in packages:
            return False
        # Depends closures stay within library sections (non-free spells
        # them "non-free/libs"); a package that provably ships a needed
        # soname joins regardless of its section.
        section = packages[name].get("Section", "").split("/")[-1]

        return section in ("libs", "oldlibs") or name in providing

    def dependencies(name, packages, provider, providing):
        """The Depends and DT_NEEDED closure of one package."""
        result = set()
        queue = [name]
        while queue:
            item = queue.pop()
            if item in result or not library_package(item, packages, providing):
                continue
            result.add(item)
            queue += dependency_names(packages[item])
            if item in profiles.known:
                for soname in profiles.known[item][3]:
                    if soname not in BRIDGED_SONAMES and soname in provider:
                        queue.append(provider[soname])
        return result - {name}

    # The soname map and the closures grow together until nothing new joins:
    # a resolved plugin dependency can bring a package whose own libraries
    # need more sonames. The Contents index backs the scanned universe up.
    fallback = contents_providers(profiles.cache)
    included = set(load)
    while True:
        for name in sorted(included):
            if name in amd64:
                profiles.of(name)
        provider = {}
        for name, (_, _, provides, _) in sorted(profiles.known.items()):
            for soname in provides:
                provider.setdefault(soname, name)
        for soname, name in fallback.items():
            if name in amd64:
                provider.setdefault(soname, name)
        providing = set(provider.values())
        grown = set(included)
        for name in sorted(included):
            if library_package(name, amd64, providing) or name in load:
                grown |= dependencies(name, amd64, provider, providing)
        unresolved = {
            soname
            for name in grown
            if name in profiles.known
            for soname in profiles.known[name][3]
            if soname not in BRIDGED_SONAMES and soname not in provider
        }
        if grown == included:
            break
        included = grown
    # A library built against a soname the snapshot no longer ships cannot
    # load under any loader; its package keeps only a download entry.
    broken = set()
    for name in sorted(load):
        needs = set(profiles.known[name][3])
        for dependency in dependencies(name, amd64, provider, providing):
            if dependency in profiles.known:
                needs |= profiles.known[dependency][3]
        gone = sorted(needs & unresolved)
        if gone:
            broken.add(name)
            print(f"demoted, sonames absent from the snapshot: {name} ({', '.join(gone)})", file=sys.stderr)
    load = [name for name in load if name not in broken]

    for machine, packages in (("x86_64", amd64), ("aarch64", arm64)):
        loadable = [name for name in load if name in packages]
        table = {}
        for name in sorted(included | set(loadable)):
            if name not in packages:
                continue
            info = packages[name]
            table[name] = {
                "filename": info["Filename"],
                "sha256": info["SHA256"],
                "load": name in loadable,
                "dependencies": sorted(
                    dependency
                    for dependency in dependencies(name, packages, provider, providing)
                    if dependency in packages
                ),
            }

        output = Path(output_dir) / f"corpus_{machine}.json"
        output.write_text(json.dumps({"snapshot": SNAPSHOT, "packages": table}, indent=1, sort_keys=True) + "\n")
        loads = sum(1 for entry in table.values() if entry["load"])
        print(f"wrote {output}: {len(table)} packages, {loads} load nodes", file=sys.stderr)


if __name__ == "__main__":
    main()
