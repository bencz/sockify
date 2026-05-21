#include <stdio.h>
#include <string.h>

#include "sockify/tls.h"

static int fail(const char *name)
{
    printf("test_tls: %s\n", name);
    return 1;
}

static int check_backend_identity(void)
{
    const char *name;

    name = sockify_tls_backend_name();
    if (name == 0 || name[0] == '\0') return fail("backend name");

#ifdef SOCKIFY_WITH_OPENSSL
    if (!sockify_tls_is_available()) return fail("openssl available");
    if (strcmp(name, "openssl") != 0) return fail("openssl backend name");
#else
    if (sockify_tls_is_available()) return fail("tls unavailable");
    if (strcmp(name, "none") != 0) return fail("none backend name");
#endif

    return 0;
}

int test_tls(void)
{
    int failures;

    failures = 0;
    failures += check_backend_identity();

    return failures;
}
