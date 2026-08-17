// Links against the versioned build of the provider, so its import carries
// @V1; at run time only the unversioned build is on the search path.

extern int dlfcn_versioned_fn(void);

int dlfcn_call_versioned(void) {
    return dlfcn_versioned_fn();
}
