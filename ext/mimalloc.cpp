// mimalloc compiled as C++, as upstream supports with MI_USE_CXX: its atomics
// then come from the vendored libc++ <atomic>, so the -nostdinc world needs
// no compiler <stdatomic.h>.
#include "mimalloc/src/static.c"
