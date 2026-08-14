# Project style settings

Per-project settings that the shared [STYLE.md](STYLE.md) delegates here.

- **Macro prefix.** Project-owned macros use `DLFCN_`. The `RTLD_*` names and
  public `dl*` spellings retain their system ABI names.
- **Namespace.** The public API is the C `dlfcn` ABI in the global namespace.
  C++ implementation details are translation-unit-local.
- **Formatter.** `./dev/style.py` formats every tracked C++ source. Assembly and
  generated symbol tables are intentionally excluded.

## Deviations

- `dlfcn.cpp` deliberately preserves the established IX factory implementation,
  including its `std::string`, `std::string_view`, and `std::unordered_map`
  storage. The standalone ELF backend and glibc ABI bridge use the same C++
  containers for owned strings and one-time symbol indexes: this low-level
  project cannot depend on IX `libstd` because it supplies `dlfcn` to that layer.
