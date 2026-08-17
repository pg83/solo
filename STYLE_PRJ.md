# Project style settings

Per-project settings that the shared [STYLE.md](STYLE.md) delegates here.

- **Macro prefix.** Project-owned macros use `DLFCN_`. The `RTLD_*` names and
  public `dl*` spellings retain their system ABI names.
- **Namespace.** The public API is the C `dlfcn` ABI in the global namespace.
  C++ implementation details are translation-unit-local.
- **Formatter.** `./dev/style.py` formats every tracked C++ source. Assembly is
  intentionally excluded.
- **Symbol tables.** No generated C++ is checked in. `lib/musl_symbols.json` and
  `lib/glibc_symbols.json` hold the data; `dev/generate_symbol_headers.py` turns
  them into `$(B)/lib/*.json.h` during the build, and the owning translation
  unit includes that header inside its anonymous namespace.

## Deviations

- `dlfcn.cpp` deliberately preserves the established IX factory implementation,
  including its `std::string`, `std::string_view`, and `std::unordered_map`
  storage. The standalone ELF backend and glibc ABI bridge use the same C++
  containers for owned strings and one-time symbol indexes: this low-level
  project cannot depend on IX `libstd` because it supplies `dlfcn` to that layer.
