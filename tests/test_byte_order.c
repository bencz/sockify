#include <stdio.h>

#include "sockify/byte_order.h"

static int fail(const char *name)
{
    printf("test_byte_order: %s\n", name);
    return 1;
}

static int check_u16(void)
{
    unsigned char input[2];
    unsigned char output[2];

    input[0] = 0x12U;
    input[1] = 0x34U;

    if (sockify_read_be16(input) != 0x1234U) return fail("read_be16");

    sockify_write_be16(output, 0xabcdU);
    if (output[0] != 0xabU) return fail("write_be16 high");
    if (output[1] != 0xcdU) return fail("write_be16 low");

    return 0;
}

static int check_u32(void)
{
    unsigned char input[4];
    unsigned char output[4];

    input[0] = 0x12U;
    input[1] = 0x34U;
    input[2] = 0x56U;
    input[3] = 0x78U;

    if (sockify_read_be32(input) != (sockify_u32)0x12345678UL) return fail("read_be32");

    sockify_write_be32(output, (sockify_u32)0x89abcdefUL);
    if (output[0] != 0x89U) return fail("write_be32 b0");
    if (output[1] != 0xabU) return fail("write_be32 b1");
    if (output[2] != 0xcdU) return fail("write_be32 b2");
    if (output[3] != 0xefU) return fail("write_be32 b3");

    return 0;
}

static int check_u64(void)
{
    unsigned char input[8];
    unsigned char output[8];
    sockify_u64 value;

    input[0] = 0x01U;
    input[1] = 0x23U;
    input[2] = 0x45U;
    input[3] = 0x67U;
    input[4] = 0x89U;
    input[5] = 0xabU;
    input[6] = 0xcdU;
    input[7] = 0xefU;

    value = sockify_read_be64(input);
    if (value != (((sockify_u64)0x01234567UL << 32) | (sockify_u64)0x89abcdefUL)) {
        return fail("read_be64");
    }

    sockify_write_be64(output, value);
    if (output[0] != input[0]) return fail("write_be64 b0");
    if (output[1] != input[1]) return fail("write_be64 b1");
    if (output[2] != input[2]) return fail("write_be64 b2");
    if (output[3] != input[3]) return fail("write_be64 b3");
    if (output[4] != input[4]) return fail("write_be64 b4");
    if (output[5] != input[5]) return fail("write_be64 b5");
    if (output[6] != input[6]) return fail("write_be64 b6");
    if (output[7] != input[7]) return fail("write_be64 b7");

    return 0;
}

int test_byte_order(void)
{
    int failures;

    failures = 0;
    failures += check_u16();
    failures += check_u32();
    failures += check_u64();

    return failures;
}
