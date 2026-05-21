#include <stdio.h>
#include <string.h>

#include "sockify/base64.h"

static int fail(const char *name)
{
    printf("test_base64: %s\n", name);
    return 1;
}

static int check_vector(const char *name, const char *input, const char *expected)
{
    char out[64];
    size_t written;
    int rc;

    written = 0;
    rc = sockify_base64_encode((const unsigned char *)input, strlen(input),
                               out, sizeof(out), &written);
    if (rc != SOCKIFY_OK) return fail(name);
    if (strcmp(out, expected) != 0) return fail(name);
    if (written != strlen(expected)) return fail(name);

    return 0;
}

static int check_overflow(void)
{
    char out[4];
    size_t written;
    int rc;

    written = 99;
    rc = sockify_base64_encode((const unsigned char *)"hello", 5,
                               out, sizeof(out), &written);
    if (rc != SOCKIFY_ERR_OVERFLOW) return fail("overflow rc");
    if (written != 0) return fail("overflow written");

    return 0;
}

int test_base64(void)
{
    int failures;

    failures = 0;
    failures += check_vector("empty", "", "");
    failures += check_vector("f", "f", "Zg==");
    failures += check_vector("fo", "fo", "Zm8=");
    failures += check_vector("foo", "foo", "Zm9v");
    failures += check_vector("hello", "hello", "aGVsbG8=");
    failures += check_overflow();

    return failures;
}
