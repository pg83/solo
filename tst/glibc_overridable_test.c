// The interposable definition, and an internal caller of it. Compiled twice:
// plain, where the global scope may interpose the call, and with -Bsymbolic,
// where DT_SYMBOLIC binds the call to this image's own definition.

int dlfcn_overridable(void) {
    return 1;
}

int dlfcn_overridable_via_self(void) {
    return dlfcn_overridable();
}
