// A global-scope interposer: once loaded with RTLD_GLOBAL, its definition of
// dlfcn_overridable must win over the one inside a later image's own
// dependency closure, like an LD_PRELOADed malloc under ld.so.

int dlfcn_overridable(void) {
    return 2;
}

int dlfcn_interposer_tag(void) {
    return 42;
}
