#ifndef SOCKIFY_WS_H
#define SOCKIFY_WS_H

#include "sockify/core.h"

#define SOCKIFY_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define SOCKIFY_WS_ACCEPT_SIZE 29U
#define SOCKIFY_WS_MAX_HTTP_REQUEST 8192U
#define SOCKIFY_WS_MAX_FRAME_PAYLOAD 65536U

#define SOCKIFY_WS_OPCODE_CONTINUATION 0x0U
#define SOCKIFY_WS_OPCODE_TEXT 0x1U
#define SOCKIFY_WS_OPCODE_BINARY 0x2U
#define SOCKIFY_WS_OPCODE_CLOSE 0x8U
#define SOCKIFY_WS_OPCODE_PING 0x9U
#define SOCKIFY_WS_OPCODE_PONG 0xaU

struct sockify_ws_message {
    int fin;
    unsigned int opcode;
    const unsigned char *payload;
    size_t payload_len;
    int frame_complete;
};

struct sockify_ws_parser {
    int state;
    unsigned char b0;
    unsigned char b1;
    unsigned int fin;
    unsigned int opcode;
    int masked;
    unsigned char ext_len_bytes[8];
    size_t ext_len_needed;
    size_t ext_len_pos;
    unsigned char mask[4];
    size_t mask_pos;
    sockify_u64 payload_len;
    sockify_u64 payload_remaining;
    sockify_u64 payload_offset;
    unsigned int fragmented_opcode;
};

int sockify_ws_accept_key(const char *client_key,
                          char *output,
                          size_t output_size);

int sockify_ws_build_handshake_response(const char *request,
                                        size_t request_len,
                                        char *response,
                                        size_t response_size,
                                        size_t *written);

int sockify_ws_build_handshake_response_ex(const char *request,
                                           size_t request_len,
                                           char *response,
                                           size_t response_size,
                                           size_t *written,
                                           size_t *consumed);

void sockify_ws_parser_init(struct sockify_ws_parser *parser);

int sockify_ws_parser_feed(struct sockify_ws_parser *parser,
                           const unsigned char *data,
                           size_t data_len,
                           size_t *used,
                           unsigned char *payload,
                           size_t payload_capacity,
                           struct sockify_ws_message *msg);

int sockify_ws_write_frame(unsigned int opcode,
                           const unsigned char *payload,
                           size_t payload_len,
                           unsigned char *output,
                           size_t output_size,
                           size_t *written);

#endif
