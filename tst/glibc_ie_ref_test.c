// A second image reaching the first one's TLS through initial-exec: the GOT
// offset written here names static TLS memory owned by another module.

#define TLS_IE __attribute__((tls_model("initial-exec")))

extern __thread int glibc_ie_tdata TLS_IE;

int* glibc_ieref_tdata_address(void) {
    return &glibc_ie_tdata;
}

int glibc_ieref_tdata_value(void) {
    return glibc_ie_tdata;
}

void glibc_ieref_tdata_add(int value) {
    glibc_ie_tdata += value;
}
