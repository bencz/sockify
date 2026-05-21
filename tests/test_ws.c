#include <stdio.h>
#include <string.h>

#include "sockify/ws.h"

static int fail(const char *name)
{
    printf("test_ws: %s\n", name);
    return 1;
}

static int check_accept_key(void)
{
    char accept[64];

    if (sockify_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", accept, sizeof(accept)) != SOCKIFY_OK) {
        return fail("accept key rc");
    }
    if (strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != 0) {
        return fail("accept key value");
    }

    return 0;
}

static int check_handshake_response(void)
{
    const char *request;
    char response[256];
    size_t written;
    int rc;

    request = "GET /websockify HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Upgrade: websocket\r\n"
              "Connection: keep-alive, Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              "Sec-WebSocket-Version: 13\r\n"
              "\r\n";

    written = 0;
    rc = sockify_ws_build_handshake_response(request, strlen(request),
                                             response, sizeof(response),
                                             &written);
    if (rc != SOCKIFY_OK) return fail("handshake rc");
    if (written == 0U) return fail("handshake written");
    if (strstr(response, "HTTP/1.1 101 Switching Protocols\r\n") == 0) return fail("handshake status");
    if (strstr(response, "Upgrade: websocket\r\n") == 0) return fail("handshake upgrade");
    if (strstr(response, "Connection: Upgrade\r\n") == 0) return fail("handshake connection");
    if (strstr(response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") == 0) {
        return fail("handshake accept");
    }

    return 0;
}

static int check_handshake_consumed_length(void)
{
    const char *request;
    char combined[512];
    char response[256];
    size_t written;
    size_t consumed;
    size_t request_len;
    int rc;

    request = "GET /websockify HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Upgrade: websocket\r\n"
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              "Sec-WebSocket-Version: 13\r\n"
              "\r\n";
    request_len = strlen(request);
    memcpy(combined, request, request_len);
    combined[request_len] = (char)0x82;
    combined[request_len + 1U] = (char)0x80;
    combined[request_len + 2U] = 0;
    combined[request_len + 3U] = 0;
    combined[request_len + 4U] = 0;
    combined[request_len + 5U] = 0;

    written = 0;
    consumed = 0;
    rc = sockify_ws_build_handshake_response_ex(combined,
                                                request_len + 6U,
                                                response,
                                                sizeof(response),
                                                &written,
                                                &consumed);
    if (rc != SOCKIFY_OK) return fail("handshake consumed rc");
    if (consumed != request_len) return fail("handshake consumed len");

    return 0;
}

static int check_invalid_handshake(void)
{
    const char *request;
    char response[256];
    size_t written;
    int rc;

    request = "GET / HTTP/1.1\r\n"
              "Host: example.com\r\n"
              "Upgrade: websocket\r\n"
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              "Sec-WebSocket-Version: 12\r\n"
              "\r\n";

    written = 99U;
    rc = sockify_ws_build_handshake_response(request, strlen(request),
                                             response, sizeof(response),
                                             &written);
    if (rc != SOCKIFY_ERR_PROTOCOL) return fail("invalid version rc");
    if (written != 0U) return fail("invalid version written");

    return 0;
}

static int check_masked_binary_frame(void)
{
    struct sockify_ws_parser parser;
    struct sockify_ws_message msg;
    unsigned char frame[8];
    unsigned char payload[8];
    size_t used;
    int rc;

    sockify_ws_parser_init(&parser);
    memset(&msg, 0, sizeof(msg));

    frame[0] = 0x82U;
    frame[1] = 0x82U;
    frame[2] = 0x01U;
    frame[3] = 0x02U;
    frame[4] = 0x03U;
    frame[5] = 0x04U;
    frame[6] = (unsigned char)('h' ^ 0x01U);
    frame[7] = (unsigned char)('i' ^ 0x02U);

    used = 0;
    rc = sockify_ws_parser_feed(&parser,
                                frame,
                                sizeof(frame),
                                &used,
                                payload,
                                sizeof(payload),
                                &msg);
    if (rc != SOCKIFY_OK) return fail("frame rc");
    if (used != sizeof(frame)) return fail("frame used");
    if (msg.opcode != SOCKIFY_WS_OPCODE_BINARY) return fail("frame opcode");
    if (msg.payload_len != 2U) return fail("frame len");
    if (!msg.frame_complete) return fail("frame complete");
    if (msg.payload[0] != 'h') return fail("frame payload 0");
    if (msg.payload[1] != 'i') return fail("frame payload 1");

    return 0;
}

static int check_parser_structs_are_small(void)
{
    if (sizeof(struct sockify_ws_message) > 64U) return fail("message size");
    if (sizeof(struct sockify_ws_parser) > 256U) return fail("parser size");

    return 0;
}

static int check_chunked_binary_frame(void)
{
    struct sockify_ws_parser parser;
    struct sockify_ws_message msg;
    unsigned char frame[12];
    unsigned char payload[3];
    size_t used;
    size_t total_used;
    int rc;
    size_t i;

    sockify_ws_parser_init(&parser);
    memset(&msg, 0, sizeof(msg));

    frame[0] = 0x82U;
    frame[1] = 0x86U;
    frame[2] = 0x01U;
    frame[3] = 0x02U;
    frame[4] = 0x03U;
    frame[5] = 0x04U;
    for (i = 0; i < 6U; i++) {
        frame[6U + i] = (unsigned char)(((unsigned char *)"abcdef")[i] ^ frame[2U + (i & 3U)]);
    }

    used = 0;
    rc = sockify_ws_parser_feed(&parser,
                                frame,
                                sizeof(frame),
                                &used,
                                payload,
                                sizeof(payload),
                                &msg);
    if (rc != SOCKIFY_OK) return fail("chunk first rc");
    if (used != 9U) return fail("chunk first used");
    if (msg.payload_len != 3U) return fail("chunk first len");
    if (msg.frame_complete) return fail("chunk first complete");
    if (memcmp(msg.payload, "abc", 3U) != 0) return fail("chunk first data");

    total_used = used;
    used = 0;
    rc = sockify_ws_parser_feed(&parser,
                                frame + total_used,
                                sizeof(frame) - total_used,
                                &used,
                                payload,
                                sizeof(payload),
                                &msg);
    if (rc != SOCKIFY_OK) return fail("chunk second rc");
    if (used != 3U) return fail("chunk second used");
    if (msg.payload_len != 3U) return fail("chunk second len");
    if (!msg.frame_complete) return fail("chunk second complete");
    if (memcmp(msg.payload, "def", 3U) != 0) return fail("chunk second data");

    return 0;
}

static int check_frame_writer(void)
{
    unsigned char payload[3];
    unsigned char frame[16];
    size_t written;

    payload[0] = 'a';
    payload[1] = 'b';
    payload[2] = 'c';

    if (sockify_ws_write_frame(SOCKIFY_WS_OPCODE_BINARY, payload, 3U,
                               frame, sizeof(frame), &written) != SOCKIFY_OK) {
        return fail("write frame rc");
    }
    if (written != 5U) return fail("write frame len");
    if (frame[0] != 0x82U) return fail("write frame first");
    if (frame[1] != 0x03U) return fail("write frame second");
    if (memcmp(frame + 2, "abc", 3U) != 0) return fail("write frame payload");

    return 0;
}

static int check_unmasked_rejected(void)
{
    struct sockify_ws_parser parser;
    struct sockify_ws_message msg;
    unsigned char frame[4];
    unsigned char payload[4];
    size_t used;

    sockify_ws_parser_init(&parser);
    frame[0] = 0x82U;
    frame[1] = 0x02U;
    frame[2] = 'o';
    frame[3] = 'k';

    if (sockify_ws_parser_feed(&parser,
                               frame,
                               sizeof(frame),
                               &used,
                               payload,
                               sizeof(payload),
                               &msg) != SOCKIFY_ERR_PROTOCOL) {
        return fail("unmasked rc");
    }

    return 0;
}

int test_ws(void)
{
    int failures;

    failures = 0;
    failures += check_accept_key();
    failures += check_handshake_response();
    failures += check_handshake_consumed_length();
    failures += check_invalid_handshake();
    failures += check_parser_structs_are_small();
    failures += check_masked_binary_frame();
    failures += check_chunked_binary_frame();
    failures += check_frame_writer();
    failures += check_unmasked_rejected();

    return failures;
}
