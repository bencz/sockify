#ifndef SOCKIFY_BUFFER_H
#define SOCKIFY_BUFFER_H

#include "sockify/core.h"

struct sockify_buffer {
    unsigned char *data;
    size_t capacity;
    size_t read_pos;
    size_t write_pos;
    size_t length;
    size_t high_water;
    size_t low_water;
};

int sockify_buffer_init(struct sockify_buffer *buf,
                        unsigned char *storage,
                        size_t capacity,
                        size_t high_water,
                        size_t low_water);

void sockify_buffer_clear(struct sockify_buffer *buf);
size_t sockify_buffer_readable(const struct sockify_buffer *buf);
size_t sockify_buffer_writable(const struct sockify_buffer *buf);
int sockify_buffer_is_high(const struct sockify_buffer *buf);
int sockify_buffer_is_low(const struct sockify_buffer *buf);

int sockify_buffer_write(struct sockify_buffer *buf,
                         const unsigned char *data,
                         size_t data_len,
                         size_t *written);

int sockify_buffer_peek(const struct sockify_buffer *buf,
                        unsigned char *out,
                        size_t out_len,
                        size_t *read_count);

int sockify_buffer_consume(struct sockify_buffer *buf,
                           size_t count,
                           size_t *consumed);

int sockify_buffer_read(struct sockify_buffer *buf,
                        unsigned char *out,
                        size_t out_len,
                        size_t *read_count);

#endif
