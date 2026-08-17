# Plan: from SoLo to a full glibc emulator

The honest frame first: a "full emulator" does not mean "implement all 5000
symbols" — it means "any real glibc dependency closure loads and behaves as it
would under glibc". So the work is driven not alphabetically through the ABI,
but by a corpus of real libraries, failing loudly on everything not yet
covered. The philosophy of the current code (fail-loud, one runtime, bridging
in place) scales — the process is what has to scale.

## Phase 2 — the hard ABI cores (where the name matches but the ABI does not)

6. **Initial-exec TLS** — the main wall: surplus static TLS as a patch to the
   vendored musl (glibc reserves ~1.6 KiB per thread, tunable) plus an offset
   allocator in the loader. Without it "fullness" is impossible:
   `-ftls-model=initial-exec` shows up in real distro builds, and a host .so
   cannot be rebuilt.

## Phase 3 — loader parity

10. **A decision on `dlclose`**: either honest refcounts + fini + unmap (with
    TLS module generations — all the DTV complexity returns), or the
    conscious compromise of "refcount and fini, but the mappings stay"
    (zombie, like NODELETE). I favor the second — 95% of the benefit without
    the use-after-unload class of bugs.

## Phase 4 — the broad corpus and the claim to "fullness"

14. GUI/GL stacks (X11, wayland with the provider from the static world — a
    killer feature nobody else has), LLVM (a stress test of 60k symbols and
    lookup performance), gstreamer (a stress test of plugin laziness).

## Explicit non-goals (record in the README)

`dlmopen`/namespaces; running glibc **executables** (a separate project —
PT_INTERP emulation on top of the same library, incidentally a natural
continuation); full NSS (`libnss_*` — a stub with a clear error message);
locale-archive (we stay in C/UTF-8, like musl).

## Status

- Done and removed from the list above: the corpus runner with per-package
  nodes, the coverage report (lcov to the coverage service), the ABI-diff
  probe (`./build abi_diff`, snapshot in dev/abi-diff.txt) and its driven
  fixes (regex, nftw, sched_param), the corpus-demanded adapters, the
  link_map facade with dlinfo, lazy binding, `DL_DEBUG=libs,bindings`,
  unlocked initializers, and the per-shim conformance battery in
  tst/glibc_shim_test.c.
- A rule generator for adapter families waits until the corpus demands more
  than a hand-written table's worth.
- The FILE facade turned out unnecessary: musl deliberately lays its FILE out
  to serve the accessors compilers inline (glibc read pointer offsets, an
  always-overflowing write end, matching EOF/ERR bits) and exports
  `__overflow`/`__uflow`; the `_IO_2_1_*` objects now resolve to musl's own
  FILE structures, and the conformance battery drives the inlined paths at
  -O2.
- Deliberately deferred: 6 (initial-exec TLS), 10 (`dlclose`).
