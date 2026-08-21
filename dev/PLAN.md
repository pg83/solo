# Plan: from SoLo to a full glibc emulator

The honest frame first: a "full emulator" does not mean "implement all 5000
symbols" — it means "any real glibc dependency closure loads and behaves as it
would under glibc". So the work is driven not alphabetically through the ABI,
but by a corpus of real libraries, failing loudly on everything not yet
covered. The philosophy of the current code (fail-loud, one runtime, bridging
in place) scales — the process is what has to scale.

## Phase 3 — loader parity

10. **A decision on `dlclose`**: either honest refcounts + fini + unmap (with
    TLS module generations — all the DTV complexity returns), or the
    conscious compromise of "refcount and fini, but the mappings stay"
    (zombie, like NODELETE). I favor the second — 95% of the benefit without
    the use-after-unload class of bugs.

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
  link_map facade with dlinfo, lazy binding, `LD_DEBUG=libs,bindings`,
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
- Initial-exec TLS landed without patching musl: the surplus arena is
  ordinary thread_local data of the host executable, so unmodified musl lays
  it out at one thread-pointer-relative offset in every thread, and the
  loader seeds future threads by writing guest `.tdata` into the
  executable's TLS template. Documented restriction: threads created before
  a `dlopen` see zeroed TLS for its modules. The jemalloc corpus node is the
  regression test.
- aarch64 landed end to end: per-architecture relocation tables, the TLSDESC
  and lazy-PLT resolvers in aarch64 assembly, hwcap-carrying ifunc calls, the
  initial-exec arena unchanged (its arithmetic never assumed a TLS variant),
  generated per-architecture glibc and musl symbol inventories, the corpus
  and smoke sysroots from the same Debian snapshot's arm64 pool, and a native
  arm64 CI job. The ABI probe (`abi_diff`) still reads the Arch package
  layout and stays x86-64-only for now.
- The loader-defect batch landed: file-backed copy-on-write segment mappings
  (page-cache sharing, names in /proc/self/maps for debuggers), ld.so's
  symbol scope order (global interposition, RTLD_DEEPBIND, DT_SYMBOLIC, and
  interposable self-references), the SysV hash fallback, the
  unversioned-provider compatibility rule confined to relocations, and
  /etc/ld.so.cache resolution. Known and accepted residue: the lazy resolver
  is not async-signal-safe, the static TLS arena is a fixed 16 KiB with no
  rollback on a failed load, and PT_GNU_PROPERTY (BTI/CET) is not carried
  into mappings.
- The broad corpus (item 14) landed as data: dev/abi_demand.py joins Debian
  popcon votes with the pinned snapshot, scans the top 1000 library packages'
  imports, and writes dev/abi-demand.txt — the bridge's priority queue,
  weighted by real installations (1450 unique imports, 1179 served natively,
  228 through stubs, none absent). dev/generate_corpus.py turns the same
  ranking into tst/corpus_<arch>.json — every popular package with a
  glibc-importing shared object becomes a load node, closures derived from
  the package index, GLIBC_PRIVATE importers ride along as dependencies only.
- The demand queue is empty: every glibc symbol the top-1000 corpus
  imports resolves natively — the backtrace pair over the vendored unwinder,
  the ucontext trio in real assembly on both architectures (glibc mcontext
  layouts, coroutine-tested), the fortified tail, the clock-parameterized
  pthread and semaphore waits, the _r database copies, glob64, obstacks,
  argz/argp, the printf-hook registry declining honestly, binary128 entry
  points (exact on aarch64, hand-converted through double on x86-64), and
  the rest of the long tail, each with a conformance-battery check.
  dev/abi-demand.txt now reads zero stubbed, zero absent.
- Deliberately deferred: 10 (`dlclose`).
