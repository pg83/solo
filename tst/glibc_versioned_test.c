// Built twice: once with a version script assigning V1, for the consumer to
// link against, and once without any versioning, served at run time. The
// consumer's dlfcn_versioned_fn@V1 reference must accept the unversioned
// definition, like ld.so's compatibility rule.

int dlfcn_versioned_fn(void) {
    return 7;
}
