// The general-dynamic view of the initial-exec module, compiled without a
// model override: both models must resolve to the same per-thread memory.

extern __thread int glibc_ie_tdata;

int* glibc_gd_tdata_address(void) {
    return &glibc_ie_tdata;
}

int glibc_gd_tdata_value(void) {
    return glibc_ie_tdata;
}
