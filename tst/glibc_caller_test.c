// A caller whose dependency closure carries dlfcn_overridable. Built twice
// with distinct sonames: one loaded normally, where the global interposer
// wins, and one with RTLD_DEEPBIND, where the closure's definition does.

extern int dlfcn_overridable(void);

int dlfcn_call_overridable(void) {
    return dlfcn_overridable();
}
