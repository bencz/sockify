#include <stdio.h>
#include <string.h>

#include "sockify/sha1.h"

static int fail(const char *name)
{
    printf("test_sha1: %s\n", name);
    return 1;
}

static void to_hex(const unsigned char digest[20], char out[41])
{
    static const char hexchars[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 20; i++) {
        out[i * 2] = hexchars[(digest[i] >> 4) & 0x0fU];
        out[(i * 2) + 1] = hexchars[digest[i] & 0x0fU];
    }
    out[40] = '\0';
}

static int check_vector(const char *name, const char *input, const char *expected)
{
    unsigned char digest[20];
    char hex[41];

    sockify_sha1((const unsigned char *)input, strlen(input), digest);
    to_hex(digest, hex);
    if (strcmp(hex, expected) != 0) {
        return fail(name);
    }

    return 0;
}

int test_sha1(void)
{
    int failures;

    failures = 0;
    failures += check_vector("empty", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    failures += check_vector("abc", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    failures += check_vector("long",
                             "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                             "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

    return failures;
}
