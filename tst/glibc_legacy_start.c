/* Model the pre-2.34 crt startup protocol using the same sysroot as the
 * modern guest: --wrap redirects its call to __libc_start_main here, and
 * the explicit callback owns DT_INIT and DT_INIT_ARRAY like __libc_csu_init.
 * The real bridge entry still receives the crt's main, argv and stack end. */
typedef void (*GuestInit)(int, char**, char**);

int printf(const char* format, ...);
void _Exit(int status);
void _init(void);
extern GuestInit __init_array_start[];
extern GuestInit __init_array_end[];

int __real___libc_start_main(int (*main)(int, char**, char**), int argc, char** argv, GuestInit init, void (*fini)(void), void (*rtld_fini)(void), void* stack_end);

static void guest_legacy_init(int argc, char** argv, char** envp) {
    if (argc < 1 || !argv[0] || envp != argv + argc + 1) {
        _Exit(90);
    }
    printf("guest legacy init\n");
    _init();
    for (GuestInit* init = __init_array_start; init != __init_array_end; ++init) {
        (*init)(argc, argv, envp);
    }
}

int __wrap___libc_start_main(int (*main)(int, char**, char**), int argc, char** argv, GuestInit init, void (*fini)(void), void (*rtld_fini)(void), void* stack_end) {
    (void)init;
    return __real___libc_start_main(main, argc, argv, guest_legacy_init, fini, rtld_fini, stack_end);
}
