// Initial-exec TLS: the compiler reads these variables through one GOT
// offset added to each thread's own thread pointer, with no call the loader
// could intercept, so they only work once the loader has placed this
// module's block in the surplus static TLS arena.

#define TLS_IE __attribute__((tls_model("initial-exec")))

__thread int glibc_ie_tdata TLS_IE = 42;
__thread int glibc_ie_tbss TLS_IE;
__thread unsigned char glibc_ie_buffer[600] TLS_IE = {7, 8, 9};
_Alignas(64) __thread int glibc_ie_aligned TLS_IE = 5;

int* glibc_ie_tdata_address(void) {
    return &glibc_ie_tdata;
}

int glibc_ie_tdata_value(void) {
    return glibc_ie_tdata;
}

void glibc_ie_tdata_set(int value) {
    glibc_ie_tdata = value;
}

int glibc_ie_tbss_value(void) {
    return glibc_ie_tbss;
}

unsigned char glibc_ie_buffer_at(int index) {
    return glibc_ie_buffer[index];
}

int* glibc_ie_aligned_address(void) {
    return &glibc_ie_aligned;
}

// The whole initial state and a mutation round-trip, runnable on any thread:
// a fresh thread must see the .tdata template, zeroed .bss, and the ELF
// alignment, and then get its own private copies to write to.
int glibc_ie_selfcheck(void) {
    if (glibc_ie_tdata != 42 || glibc_ie_tbss != 0) {
        return 1;
    }
    if (glibc_ie_buffer[0] != 7 || glibc_ie_buffer[1] != 8 || glibc_ie_buffer[2] != 9 || glibc_ie_buffer[599] != 0) {
        return 2;
    }
    if (glibc_ie_aligned != 5 || (unsigned long)&glibc_ie_aligned % 64 != 0) {
        return 3;
    }
    glibc_ie_tdata = 1000;
    glibc_ie_tbss = 2000;
    glibc_ie_buffer[0] = 70;
    if (glibc_ie_tdata != 1000 || glibc_ie_tbss != 2000 || glibc_ie_buffer[0] != 70) {
        return 4;
    }

    return 0;
}
