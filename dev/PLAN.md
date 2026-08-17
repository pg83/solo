# Plan: from SoLo to a full glibc emulator

The honest frame first: a "full emulator" does not mean "implement all 5000
symbols" — it means "any real glibc dependency closure loads and behaves as it
would under glibc". So the work is driven not alphabetically through the ABI,
but by a corpus of real libraries, failing loudly on everything not yet
covered. The philosophy of the current code (fail-loud, one runtime, bridging
in place) scales — the process is what has to scale.

## Phase 0 — measurement infrastructure (everything else is blind without it)

1. **Corpus runner** — a generalization of arch_smoke: a list of real packages
   (sqlite, openssl, curl, ffmpeg, SDL2, X11/wayland clients, all of libGL,
   LLVM, gstreamer), downloaded by sha256 as today; every .so is loaded
   through SoLo: the full relocation cycle plus initializers. That alone is
   the strongest smoke test: relocation pulls in the whole import graph.
2. **Coverage report in CI**: over the corpus — the percentage of resolved
   symbols, the top missing ones with versions, how many landed in stubs.
   Every commit moves the number — progress and regressions are visible.
3. **ABI-diff probe**: a dev script that, with two compilations (against glibc
   and musl headers), compares sizes/offsets of structures and constants from
   the suspect list (`regex_t`, `FILE`, `struct dirent`, `glob_t`, `sigset_t`,
   `O_*`, `SIG_*`, ...) and generates a table of "matches / needs a shim /
   needs an implementation". This turns unknown-unknowns — the main source of
   silent emulation bugs — into a table.

## Phase 1 — scaling coverage (cheap breadth)

4. **Rule-generated adapters instead of the hand-written table**: the families
   with a mechanical correspondence — `*64` (LFS), `__*_chk` (fortify),
   `__isoc99_*`/`__isoc23_*`, the locale `_l` variants, the `__xstat` family —
   are described by name-transformation rules plus a wrapper template in
   `dev/`, not by 250 hand-written lines. `glibc_symbols.json` already holds
   the full inventory with versions and kinds — that is the generator's input.
5. **Passthrough validation**: today "a musl symbol with the same name" is
   assumed compatible by default. Run the list through the ABI diff and mark
   the exceptions explicitly (for example `regcomp`: `regex_t` has a different
   layout — passthrough is only correct if the object never crosses the world
   boundary; in the dlopen model it usually does not, but that has to be
   decided consciously and written down).

## Phase 2 — the hard ABI cores (where the name matches but the ABI does not)

6. **Initial-exec TLS** — the main wall: surplus static TLS as a patch to the
   vendored musl (glibc reserves ~1.6 KiB per thread, tunable) plus an offset
   allocator in the loader. Without it "fullness" is impossible:
   `-ftls-model=initial-exec` shows up in real distro builds, and a host .so
   cannot be rebuilt.
7. **A glibc-FILE facade**: compilers inline `putc_unlocked`/`getc_unlocked`
   straight into DSO code — it reaches into `_IO_FILE` fields past any
   functions. We need genuine glibc-layout objects (`_IO_2_1_std{in,out,err}_`
   and a factory for `fopen`) whose buffer pointers and `_IO_jump_t` vtable
   lead into our adapters over musl FILEs. That is the only honest way to
   retire the current PROT_NONE mapping of the stdio objects.
8. **A `link_map` facade**: real code casts the dlopen handle to
   `struct link_map*` and walks `l_name`/`l_addr`/`l_next`; plus
   `dlinfo(RTLD_DI_LINKMAP)`. Our handle must carry a glibc-compatible field
   prefix. `dlinfo`/`dladdr1` get closed along the way.

## Phase 3 — loader parity

9. **Lazy binding**: binding is eager today — a DSO with a PLT reference to a
   symbol nobody provides will not load at all, although under glibc it would
   live until the call. Our own binder stub (writing into the GOT on first
   call) — medium complexity, a large compatibility win for plugin
   ecosystems.
10. **A decision on `dlclose`**: either honest refcounts + fini + unmap (with
    TLS module generations — all the DTV complexity returns), or the
    conscious compromise of "refcount and fini, but the mappings stay"
    (zombie, like NODELETE). I favor the second — 95% of the benefit without
    the use-after-unload class of bugs.
11. **ld.so-grade diagnostics**: an analogue of `LD_DEBUG=bindings,libs` (we
    already have DL_STUB_DEBUG — unify), so a foreign closure can be debugged
    without reading our code.
12. Unlock `runInitializers` (an initializer waiting on a thread that waits on
    our mutex is a known deadlock under glibc too, but ours is easier to fix).

## Phase 4 — the broad corpus and the claim to "fullness"

13. Conformance tests per API family: small programs built with a real gcc
    against a real glibc, executed through SoLo and natively — the outputs
    compared. That is the definition of an "emulator": corpus plus
    conformance, both green.
14. GUI/GL stacks (X11, wayland with the provider from the static world — a
    killer feature nobody else has), LLVM (a stress test of 60k symbols and
    lookup performance), gstreamer (a stress test of plugin laziness).

## Explicit non-goals (record in the README)

`dlmopen`/namespaces; running glibc **executables** (a separate project —
PT_INTERP emulation on top of the same library, incidentally a natural
continuation); full NSS (`libnss_*` — a stub with a clear error message);
locale-archive (we stay in C/UTF-8, like musl).

The order is what it is because 0→1 give a fast rise in the coverage number
and a regression corpus, 2 is the three real walls (IE TLS, FILE, link_map)
that everything "broad" crashes against, and 3 is quality of life once the
corpus is already large.
