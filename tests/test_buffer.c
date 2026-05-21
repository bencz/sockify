#include <stdio.h>
#include <string.h>

#include "sockify/buffer.h"

static int fail(const char *name)
{
    printf("test_buffer: %s\n", name);
    return 1;
}

static int check_basic_flow(void)
{
    unsigned char storage[8];
    unsigned char out[8];
    unsigned char data[5];
    struct sockify_buffer buf;
    size_t count;

    data[0] = 'a';
    data[1] = 'b';
    data[2] = 'c';
    data[3] = 'd';
    data[4] = 'e';

    if (sockify_buffer_init(&buf, storage, sizeof(storage), 5U, 2U) != SOCKIFY_OK) return fail("init");
    if (sockify_buffer_write(&buf, data, sizeof(data), &count) != SOCKIFY_OK) return fail("write");
    if (count != 5U) return fail("write count");
    if (sockify_buffer_readable(&buf) != 5U) return fail("readable");
    if (!sockify_buffer_is_high(&buf)) return fail("high water");

    memset(out, 0, sizeof(out));
    if (sockify_buffer_read(&buf, out, 4U, &count) != SOCKIFY_OK) return fail("read");
    if (count != 4U) return fail("read count");
    if (memcmp(out, "abcd", 4U) != 0) return fail("read data");
    if (!sockify_buffer_is_low(&buf)) return fail("low water");

    return 0;
}

static int check_wraparound(void)
{
    unsigned char storage[5];
    unsigned char out[5];
    struct sockify_buffer buf;
    size_t count;

    if (sockify_buffer_init(&buf, storage, sizeof(storage), 4U, 1U) != SOCKIFY_OK) return fail("wrap init");
    if (sockify_buffer_write(&buf, (const unsigned char *)"abcd", 4U, &count) != SOCKIFY_OK) return fail("wrap write 1");
    if (sockify_buffer_read(&buf, out, 3U, &count) != SOCKIFY_OK) return fail("wrap read 1");
    if (sockify_buffer_write(&buf, (const unsigned char *)"xyz", 3U, &count) != SOCKIFY_OK) return fail("wrap write 2");
    if (count != 3U) return fail("wrap write count");
    if (sockify_buffer_read(&buf, out, 4U, &count) != SOCKIFY_OK) return fail("wrap read 2");
    if (count != 4U) return fail("wrap read count");
    if (memcmp(out, "dxyz", 4U) != 0) return fail("wrap data");

    return 0;
}

static int check_truncation(void)
{
    unsigned char storage[3];
    struct sockify_buffer buf;
    size_t count;

    if (sockify_buffer_init(&buf, storage, sizeof(storage), 3U, 1U) != SOCKIFY_OK) return fail("trunc init");
    if (sockify_buffer_write(&buf, (const unsigned char *)"abcd", 4U, &count) != SOCKIFY_ERR_OVERFLOW) {
        return fail("trunc rc");
    }
    if (count != 3U) return fail("trunc count");
    if (sockify_buffer_writable(&buf) != 0U) return fail("trunc writable");

    return 0;
}

int test_buffer(void)
{
    int failures;

    failures = 0;
    failures += check_basic_flow();
    failures += check_wraparound();
    failures += check_truncation();

    return failures;
}
