#include "sockify/buffer.h"

/*
 * Fixed-storage ring buffer. The caller owns the backing storage,
 * so the buffer never allocates. read_pos/write_pos index into the
 * ring modulo capacity; length is the authoritative count of bytes
 * currently held, which keeps the full/empty cases unambiguous.
 */

int sockify_buffer_init(struct sockify_buffer *buf,
                        unsigned char *storage,
                        size_t capacity,
                        size_t high_water,
                        size_t low_water)
{
    if (buf == 0 || storage == 0 || capacity == 0U) {
        return SOCKIFY_ERR_INVALID;
    }
    if (high_water > capacity || low_water > high_water) {
        return SOCKIFY_ERR_INVALID;
    }

    buf->data = storage;
    buf->capacity = capacity;
    buf->read_pos = 0;
    buf->write_pos = 0;
    buf->length = 0;
    buf->high_water = high_water;
    buf->low_water = low_water;
    return SOCKIFY_OK;
}

void sockify_buffer_clear(struct sockify_buffer *buf)
{
    if (buf == 0) {
        return;
    }
    buf->read_pos = 0;
    buf->write_pos = 0;
    buf->length = 0;
}

size_t sockify_buffer_readable(const struct sockify_buffer *buf)
{
    return buf->length;
}

size_t sockify_buffer_writable(const struct sockify_buffer *buf)
{
    return buf->capacity - buf->length;
}

int sockify_buffer_is_high(const struct sockify_buffer *buf)
{
    return buf->length >= buf->high_water;
}

int sockify_buffer_is_low(const struct sockify_buffer *buf)
{
    return buf->length <= buf->low_water;
}

int sockify_buffer_write(struct sockify_buffer *buf,
                         const unsigned char *data,
                         size_t data_len,
                         size_t *written)
{
    size_t writable;
    size_t to_write;
    size_t i;

    if (written != 0) {
        *written = 0;
    }
    if (buf == 0 || (data == 0 && data_len != 0)) {
        return SOCKIFY_ERR_INVALID;
    }

    writable = buf->capacity - buf->length;
    to_write = data_len < writable ? data_len : writable;

    for (i = 0; i < to_write; i++) {
        buf->data[buf->write_pos] = data[i];
        buf->write_pos++;
        if (buf->write_pos == buf->capacity) {
            buf->write_pos = 0;
        }
    }
    buf->length += to_write;

    if (written != 0) {
        *written = to_write;
    }
    if (to_write < data_len) {
        return SOCKIFY_ERR_OVERFLOW;
    }
    return SOCKIFY_OK;
}

int sockify_buffer_peek(const struct sockify_buffer *buf,
                        unsigned char *out,
                        size_t out_len,
                        size_t *read_count)
{
    size_t to_read;
    size_t pos;
    size_t i;

    if (read_count != 0) {
        *read_count = 0;
    }
    if (buf == 0 || (out == 0 && out_len != 0)) {
        return SOCKIFY_ERR_INVALID;
    }

    to_read = out_len < buf->length ? out_len : buf->length;
    pos = buf->read_pos;
    for (i = 0; i < to_read; i++) {
        out[i] = buf->data[pos];
        pos++;
        if (pos == buf->capacity) {
            pos = 0;
        }
    }

    if (read_count != 0) {
        *read_count = to_read;
    }
    return SOCKIFY_OK;
}

int sockify_buffer_consume(struct sockify_buffer *buf,
                           size_t count,
                           size_t *consumed)
{
    size_t to_consume;

    if (consumed != 0) {
        *consumed = 0;
    }
    if (buf == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    to_consume = count < buf->length ? count : buf->length;
    buf->read_pos += to_consume;
    while (buf->read_pos >= buf->capacity) {
        buf->read_pos -= buf->capacity;
    }
    buf->length -= to_consume;

    if (consumed != 0) {
        *consumed = to_consume;
    }
    return SOCKIFY_OK;
}

int sockify_buffer_read(struct sockify_buffer *buf,
                        unsigned char *out,
                        size_t out_len,
                        size_t *read_count)
{
    size_t count;
    int rc;

    if (read_count != 0) {
        *read_count = 0;
    }

    rc = sockify_buffer_peek(buf, out, out_len, &count);
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    sockify_buffer_consume(buf, count, 0);

    if (read_count != 0) {
        *read_count = count;
    }
    return SOCKIFY_OK;
}
