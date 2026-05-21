#include <string.h>

#include "sockify/byte_order.h"
#include "sockify/ws.h"

#define WS_STATE_HEADER_1 0
#define WS_STATE_HEADER_2 1
#define WS_STATE_EXT_LEN 2
#define WS_STATE_MASK 3
#define WS_STATE_PAYLOAD 4

void sockify_ws_parser_init(struct sockify_ws_parser *parser)
{
    if (parser == 0) {
        return;
    }
    memset(parser, 0, sizeof(*parser));
    parser->state = WS_STATE_HEADER_1;
}

static int is_control_opcode(unsigned int opcode)
{
    return opcode >= 0x8U;
}

static int valid_opcode(unsigned int opcode)
{
    return opcode == SOCKIFY_WS_OPCODE_CONTINUATION ||
           opcode == SOCKIFY_WS_OPCODE_TEXT ||
           opcode == SOCKIFY_WS_OPCODE_BINARY ||
           opcode == SOCKIFY_WS_OPCODE_CLOSE ||
           opcode == SOCKIFY_WS_OPCODE_PING ||
           opcode == SOCKIFY_WS_OPCODE_PONG;
}

static int reset_frame(struct sockify_ws_parser *parser)
{
    if (parser->opcode == SOCKIFY_WS_OPCODE_TEXT ||
        parser->opcode == SOCKIFY_WS_OPCODE_BINARY) {
        if (!parser->fin) {
            if (parser->fragmented_opcode != 0U) {
                return SOCKIFY_ERR_PROTOCOL;
            }
            parser->fragmented_opcode = parser->opcode;
        }
    } else if (parser->opcode == SOCKIFY_WS_OPCODE_CONTINUATION) {
        if (parser->fragmented_opcode == 0U) {
            return SOCKIFY_ERR_PROTOCOL;
        }
        if (parser->fin) {
            parser->fragmented_opcode = 0U;
        }
    }

    parser->state = WS_STATE_HEADER_1;
    parser->b0 = 0;
    parser->b1 = 0;
    parser->fin = 0;
    parser->opcode = 0;
    parser->masked = 0;
    parser->ext_len_needed = 0;
    parser->ext_len_pos = 0;
    parser->mask_pos = 0;
    parser->payload_len = 0;
    parser->payload_remaining = 0;
    parser->payload_offset = 0;
    return SOCKIFY_OK;
}

static void prepare_message(struct sockify_ws_parser *parser,
                            struct sockify_ws_message *msg,
                            const unsigned char *payload,
                            size_t payload_len,
                            int frame_complete)
{
    msg->fin = parser->fin ? 1 : 0;
    msg->opcode = parser->opcode;
    msg->payload = payload;
    msg->payload_len = payload_len;
    msg->frame_complete = frame_complete ? 1 : 0;
}

static int validate_frame_header(struct sockify_ws_parser *parser)
{
    if (is_control_opcode(parser->opcode)) {
        if (!parser->fin || parser->payload_len > 125U) {
            return SOCKIFY_ERR_PROTOCOL;
        }
    } else if (parser->opcode == SOCKIFY_WS_OPCODE_CONTINUATION) {
        if (parser->fragmented_opcode == 0U) {
            return SOCKIFY_ERR_PROTOCOL;
        }
    } else if (parser->fragmented_opcode != 0U) {
        return SOCKIFY_ERR_PROTOCOL;
    }
    return SOCKIFY_OK;
}

static int finish_length(struct sockify_ws_parser *parser)
{
    if (parser->ext_len_needed == 2U) {
        parser->payload_len = (sockify_u64)sockify_read_be16(parser->ext_len_bytes);
        if (parser->payload_len < 126U) {
            return SOCKIFY_ERR_PROTOCOL;
        }
    } else if (parser->ext_len_needed == 8U) {
        parser->payload_len = sockify_read_be64(parser->ext_len_bytes);
        if (parser->payload_len < 65536U ||
            (parser->ext_len_bytes[0] & 0x80U) != 0U) {
            return SOCKIFY_ERR_PROTOCOL;
        }
    }
    parser->payload_remaining = parser->payload_len;
    return validate_frame_header(parser);
}

static int emit_empty_frame(struct sockify_ws_parser *parser,
                            struct sockify_ws_message *msg)
{
    int rc;

    prepare_message(parser, msg, 0, 0, 1);
    rc = reset_frame(parser);
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    return SOCKIFY_OK;
}

static size_t min_size(size_t a, size_t b)
{
    if (a < b) {
        return a;
    }
    return b;
}

int sockify_ws_parser_feed(struct sockify_ws_parser *parser,
                           const unsigned char *data,
                           size_t data_len,
                           size_t *used,
                           unsigned char *payload,
                           size_t payload_capacity,
                           struct sockify_ws_message *msg)
{
    size_t pos;
    size_t available;
    size_t chunk_len;
    size_t i;
    int rc;

    if (used != 0) {
        *used = 0;
    }
    if (parser == 0 || used == 0 || msg == 0 ||
        (data_len != 0U && data == 0) ||
        (payload_capacity != 0U && payload == 0)) {
        return SOCKIFY_ERR_INVALID;
    }

    pos = 0;
    memset(msg, 0, sizeof(*msg));

    while (pos < data_len || parser->state == WS_STATE_PAYLOAD) {
        if (parser->state == WS_STATE_HEADER_1) {
            if (pos >= data_len) break;
            parser->b0 = data[pos++];
            parser->fin = (parser->b0 & 0x80U) != 0U;
            parser->opcode = parser->b0 & 0x0fU;
            if ((parser->b0 & 0x70U) != 0U || !valid_opcode(parser->opcode)) {
                *used = pos;
                return SOCKIFY_ERR_PROTOCOL;
            }
            parser->state = WS_STATE_HEADER_2;
        } else if (parser->state == WS_STATE_HEADER_2) {
            if (pos >= data_len) break;
            parser->b1 = data[pos++];
            parser->masked = (parser->b1 & 0x80U) != 0U;
            parser->payload_len = (sockify_u64)(parser->b1 & 0x7fU);
            if (!parser->masked) {
                *used = pos;
                return SOCKIFY_ERR_PROTOCOL;
            }
            if (parser->payload_len == 126U) {
                parser->ext_len_needed = 2U;
                parser->ext_len_pos = 0;
                parser->state = WS_STATE_EXT_LEN;
            } else if (parser->payload_len == 127U) {
                parser->ext_len_needed = 8U;
                parser->ext_len_pos = 0;
                parser->state = WS_STATE_EXT_LEN;
            } else {
                parser->payload_remaining = parser->payload_len;
                rc = validate_frame_header(parser);
                if (rc != SOCKIFY_OK) {
                    *used = pos;
                    return rc;
                }
                parser->state = WS_STATE_MASK;
            }
        } else if (parser->state == WS_STATE_EXT_LEN) {
            if (pos >= data_len) break;
            parser->ext_len_bytes[parser->ext_len_pos++] = data[pos++];
            if (parser->ext_len_pos == parser->ext_len_needed) {
                rc = finish_length(parser);
                if (rc != SOCKIFY_OK) {
                    *used = pos;
                    return rc;
                }
                parser->state = WS_STATE_MASK;
            }
        } else if (parser->state == WS_STATE_MASK) {
            if (pos >= data_len) break;
            parser->mask[parser->mask_pos++] = data[pos++];
            if (parser->mask_pos == 4U) {
                parser->state = WS_STATE_PAYLOAD;
                if (parser->payload_remaining == 0U) {
                    *used = pos;
                    return emit_empty_frame(parser, msg);
                }
            }
        } else if (parser->state == WS_STATE_PAYLOAD) {
            available = data_len - pos;
            if (available == 0U) {
                break;
            }
            if (payload_capacity == 0U) {
                *used = pos;
                return SOCKIFY_ERR_OVERFLOW;
            }
            if (is_control_opcode(parser->opcode) &&
                parser->payload_remaining > (sockify_u64)payload_capacity) {
                *used = pos;
                return SOCKIFY_ERR_OVERFLOW;
            }
            chunk_len = min_size(available, payload_capacity);
            if ((sockify_u64)chunk_len > parser->payload_remaining) {
                chunk_len = (size_t)parser->payload_remaining;
            }
            for (i = 0; i < chunk_len; i++) {
                payload[i] = (unsigned char)(data[pos + i] ^
                    parser->mask[(size_t)((parser->payload_offset + (sockify_u64)i) & 3U)]);
            }
            pos += chunk_len;
            parser->payload_offset += (sockify_u64)chunk_len;
            parser->payload_remaining -= (sockify_u64)chunk_len;
            prepare_message(parser,
                            msg,
                            payload,
                            chunk_len,
                            parser->payload_remaining == 0U);
            if (parser->payload_remaining == 0U) {
                rc = reset_frame(parser);
                if (rc != SOCKIFY_OK) {
                    *used = pos;
                    return rc;
                }
            }
            *used = pos;
            return SOCKIFY_OK;
        } else {
            *used = pos;
            return SOCKIFY_ERR_INVALID;
        }
    }

    *used = pos;
    return SOCKIFY_ERR_AGAIN;
}

int sockify_ws_write_frame(unsigned int opcode,
                           const unsigned char *payload,
                           size_t payload_len,
                           unsigned char *output,
                           size_t output_size,
                           size_t *written)
{
    size_t header_len;

    if (written != 0) {
        *written = 0;
    }
    if (output == 0 || written == 0 || (payload_len != 0U && payload == 0)) {
        return SOCKIFY_ERR_INVALID;
    }
    if (!valid_opcode(opcode)) {
        return SOCKIFY_ERR_PROTOCOL;
    }
    if (is_control_opcode(opcode) && payload_len > 125U) {
        return SOCKIFY_ERR_PROTOCOL;
    }

    if (payload_len <= 125U) {
        header_len = 2U;
    } else if (payload_len <= 65535U) {
        header_len = 4U;
    } else {
        header_len = 10U;
    }

    if (output_size < header_len + payload_len) {
        return SOCKIFY_ERR_OVERFLOW;
    }

    output[0] = (unsigned char)(0x80U | (opcode & 0x0fU));
    if (payload_len <= 125U) {
        output[1] = (unsigned char)payload_len;
    } else if (payload_len <= 65535U) {
        output[1] = 126U;
        sockify_write_be16(output + 2, (sockify_u16)payload_len);
    } else {
        output[1] = 127U;
        sockify_write_be64(output + 2, (sockify_u64)payload_len);
    }

    if (payload_len != 0U) {
        memcpy(output + header_len, payload, payload_len);
    }
    *written = header_len + payload_len;

    return SOCKIFY_OK;
}
