// TLS bigger than the whole static arena. Under the default model the module
// must still load, served from the dynamic per-thread blocks; compiled with
// BIG_TLS_IE the initial-exec relocations must fail the load loudly instead.

#ifdef BIG_TLS_IE
    #define TLS_MODEL __attribute__((tls_model("initial-exec")))
#else
    #define TLS_MODEL
#endif

__thread unsigned char glibc_big_tls[64 * 1024] TLS_MODEL = {11};

unsigned char* glibc_big_tls_address(void) {
    return glibc_big_tls;
}

unsigned char glibc_big_tls_first(void) {
    return glibc_big_tls[0];
}
