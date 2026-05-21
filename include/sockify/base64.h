#ifndef SOCKIFY_BASE64_H
#define SOCKIFY_BASE64_H

#include "sockify/core.h"

int sockify_base64_encode(const unsigned char *input,
                          size_t input_len,
                          char *output,
                          size_t output_size,
                          size_t *written);

#endif
