#ifndef SOCKIFY_SHA1_H
#define SOCKIFY_SHA1_H

#include "sockify/core.h"

void sockify_sha1(const unsigned char *input, size_t input_len, unsigned char digest[20]);

#endif
