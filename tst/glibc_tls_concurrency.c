/* Built as separate IE and GD modules. Each thread must get a private copy
 * of both initialized and zero-filled data, including the ELF alignment. */
__thread int tls_concurrency_tdata = 42;
__thread int tls_concurrency_tbss;
__thread unsigned char tls_concurrency_buffer[600] = {7, 8, 9};
_Alignas(64) __thread int tls_concurrency_aligned = 5;

int* tls_concurrency_address(void) {
    return &tls_concurrency_tdata;
}

int tls_concurrency_check(int value) {
    if (tls_concurrency_tdata != 42 || tls_concurrency_tbss != 0) {
        return 1;
    }
    if (tls_concurrency_buffer[0] != 7 || tls_concurrency_buffer[1] != 8 || tls_concurrency_buffer[2] != 9 || tls_concurrency_buffer[599] != 0) {
        return 2;
    }
    if (tls_concurrency_aligned != 5 || (unsigned long)&tls_concurrency_aligned % 64) {
        return 3;
    }
    tls_concurrency_tdata = value;
    tls_concurrency_tbss = value + 1;
    tls_concurrency_buffer[0] = (unsigned char)value;
    tls_concurrency_aligned = value + 2;
    return 0;
}

int tls_concurrency_verify(int value) {
    return tls_concurrency_tdata != value || tls_concurrency_tbss != value + 1 || tls_concurrency_buffer[0] != (unsigned char)value || tls_concurrency_aligned != value + 2;
}
