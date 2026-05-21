#ifndef SOCKIFY_BYTE_ORDER_H
#define SOCKIFY_BYTE_ORDER_H

#include "sockify/core.h"

sockify_u16 sockify_read_be16(const unsigned char *buf);
sockify_u32 sockify_read_be32(const unsigned char *buf);
sockify_u64 sockify_read_be64(const unsigned char *buf);

void sockify_write_be16(unsigned char *buf, sockify_u16 value);
void sockify_write_be32(unsigned char *buf, sockify_u32 value);
void sockify_write_be64(unsigned char *buf, sockify_u64 value);

#endif
