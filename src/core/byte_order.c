#include "sockify/byte_order.h"

sockify_u16 sockify_read_be16(const unsigned char *buf)
{
    return (sockify_u16)(((sockify_u16)buf[0] << 8) | (sockify_u16)buf[1]);
}

sockify_u32 sockify_read_be32(const unsigned char *buf)
{
    return ((sockify_u32)buf[0] << 24) |
           ((sockify_u32)buf[1] << 16) |
           ((sockify_u32)buf[2] << 8) |
           (sockify_u32)buf[3];
}

sockify_u64 sockify_read_be64(const unsigned char *buf)
{
    return ((sockify_u64)buf[0] << 56) |
           ((sockify_u64)buf[1] << 48) |
           ((sockify_u64)buf[2] << 40) |
           ((sockify_u64)buf[3] << 32) |
           ((sockify_u64)buf[4] << 24) |
           ((sockify_u64)buf[5] << 16) |
           ((sockify_u64)buf[6] << 8) |
           (sockify_u64)buf[7];
}

void sockify_write_be16(unsigned char *buf, sockify_u16 value)
{
    buf[0] = (unsigned char)((value >> 8) & 0xffU);
    buf[1] = (unsigned char)(value & 0xffU);
}

void sockify_write_be32(unsigned char *buf, sockify_u32 value)
{
    buf[0] = (unsigned char)((value >> 24) & 0xffU);
    buf[1] = (unsigned char)((value >> 16) & 0xffU);
    buf[2] = (unsigned char)((value >> 8) & 0xffU);
    buf[3] = (unsigned char)(value & 0xffU);
}

void sockify_write_be64(unsigned char *buf, sockify_u64 value)
{
    buf[0] = (unsigned char)((value >> 56) & 0xffU);
    buf[1] = (unsigned char)((value >> 48) & 0xffU);
    buf[2] = (unsigned char)((value >> 40) & 0xffU);
    buf[3] = (unsigned char)((value >> 32) & 0xffU);
    buf[4] = (unsigned char)((value >> 24) & 0xffU);
    buf[5] = (unsigned char)((value >> 16) & 0xffU);
    buf[6] = (unsigned char)((value >> 8) & 0xffU);
    buf[7] = (unsigned char)(value & 0xffU);
}
