#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "sockify/base64.h"
#include "sockify/sha1.h"
#include "sockify/ws.h"

static int ascii_tolower(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int ci_equal_n(const char *a, const char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (ascii_tolower((unsigned char)a[i]) != ascii_tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

static int ci_equal_string_n(const char *a, size_t a_len, const char *b)
{
    size_t b_len;

    b_len = strlen(b);
    if (a_len != b_len) {
        return 0;
    }
    return ci_equal_n(a, b, a_len);
}

static int is_token_sep(char c)
{
    return c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int ci_contains_token(const char *value, size_t value_len, const char *token)
{
    size_t token_len;
    size_t i;
    size_t j;

    token_len = strlen(token);
    i = 0;
    while (i < value_len) {
        while (i < value_len && is_token_sep(value[i])) {
            i++;
        }
        j = i;
        while (j < value_len && !is_token_sep(value[j])) {
            j++;
        }
        if ((j - i) == token_len && ci_equal_n(value + i, token, token_len)) {
            return 1;
        }
        i = j + 1U;
    }
    return 0;
}

static void trim_span(const char **start, size_t *len)
{
    const char *s;
    size_t n;

    s = *start;
    n = *len;

    while (n != 0U && (*s == ' ' || *s == '\t')) {
        s++;
        n--;
    }
    while (n != 0U && (s[n - 1U] == ' ' || s[n - 1U] == '\t')) {
        n--;
    }

    *start = s;
    *len = n;
}

static int memory_contains(const char *haystack, size_t hay_len,
                           const char *needle, size_t needle_len)
{
    size_t i;

    if (needle_len == 0U) {
        return 1;
    }
    if (hay_len < needle_len) {
        return 0;
    }
    for (i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int find_header_end(const char *request, size_t request_len, size_t *header_len)
{
    size_t i;

    if (request_len > SOCKIFY_WS_MAX_HTTP_REQUEST) {
        return SOCKIFY_ERR_OVERFLOW;
    }

    for (i = 0; i + 3U < request_len; i++) {
        if (request[i] == '\r' && request[i + 1U] == '\n' &&
            request[i + 2U] == '\r' && request[i + 3U] == '\n') {
            *header_len = i + 4U;
            return SOCKIFY_OK;
        }
    }

    return SOCKIFY_ERR_AGAIN;
}

int sockify_ws_accept_key(const char *client_key,
                          char *output,
                          size_t output_size)
{
    unsigned char digest[20];
    char combined[256];
    size_t key_len;
    size_t guid_len;
    size_t written;

    if (client_key == 0 || output == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    key_len = strlen(client_key);
    guid_len = strlen(SOCKIFY_WS_GUID);
    if (key_len == 0U || key_len + guid_len >= sizeof(combined)) {
        return SOCKIFY_ERR_INVALID;
    }

    if (output_size < SOCKIFY_WS_ACCEPT_SIZE) {
        output[0] = '\0';
        return SOCKIFY_ERR_OVERFLOW;
    }

    memcpy(combined, client_key, key_len);
    memcpy(combined + key_len, SOCKIFY_WS_GUID, guid_len);
    sockify_sha1((const unsigned char *)combined, key_len + guid_len, digest);

    written = 0;
    return sockify_base64_encode(digest, sizeof(digest), output, output_size, &written);
}

int sockify_ws_build_handshake_response(const char *request,
                                        size_t request_len,
                                        char *response,
                                        size_t response_size,
                                        size_t *written)
{
    size_t consumed;

    consumed = 0;
    return sockify_ws_build_handshake_response_ex(request,
                                                 request_len,
                                                 response,
                                                 response_size,
                                                 written,
                                                 &consumed);
}

int sockify_ws_build_handshake_response_ex(const char *request,
                                           size_t request_len,
                                           char *response,
                                           size_t response_size,
                                           size_t *written,
                                           size_t *consumed)
{
    size_t header_len;
    size_t line_start;
    size_t line_end;
    size_t name_len;
    size_t value_len;
    const char *name;
    const char *value;
    const char *key_value;
    size_t key_len;
    int saw_upgrade;
    int saw_connection;
    int saw_version;
    int saw_key;
    char key_copy[128];
    char accept[SOCKIFY_WS_ACCEPT_SIZE];
    char temp[256];
    size_t temp_len;
    size_t i;
    int rc;

    if (written != 0) {
        *written = 0;
    }
    if (consumed != 0) {
        *consumed = 0;
    }
    if (request == 0 || response == 0 || written == 0 || consumed == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    rc = find_header_end(request, request_len, &header_len);
    if (rc != SOCKIFY_OK) {
        return rc;
    }

    line_end = 0;
    while (line_end + 1U < header_len) {
        if (request[line_end] == '\r' && request[line_end + 1U] == '\n') {
            break;
        }
        line_end++;
    }

    if (line_end < 14U) {
        return SOCKIFY_ERR_PROTOCOL;
    }
    if (!ci_equal_n(request, "GET ", 4U)) {
        return SOCKIFY_ERR_PROTOCOL;
    }
    if (!memory_contains(request, line_end, " HTTP/1.1", 9U) &&
        !memory_contains(request, line_end, " HTTP/1.0", 9U)) {
        return SOCKIFY_ERR_PROTOCOL;
    }

    saw_upgrade = 0;
    saw_connection = 0;
    saw_version = 0;
    saw_key = 0;
    key_value = 0;
    key_len = 0;

    line_start = line_end + 2U;
    while (line_start + 1U < header_len) {
        if (request[line_start] == '\r' && request[line_start + 1U] == '\n') {
            break;
        }

        line_end = line_start;
        while (line_end + 1U < header_len) {
            if (request[line_end] == '\r' && request[line_end + 1U] == '\n') {
                break;
            }
            line_end++;
        }

        name = request + line_start;
        name_len = 0;
        while (line_start + name_len < line_end && request[line_start + name_len] != ':') {
            name_len++;
        }
        if (line_start + name_len >= line_end) {
            return SOCKIFY_ERR_PROTOCOL;
        }

        value = request + line_start + name_len + 1U;
        value_len = line_end - (line_start + name_len + 1U);
        trim_span(&value, &value_len);

        if (ci_equal_string_n(name, name_len, "Upgrade")) {
            if (ci_equal_string_n(value, value_len, "websocket")) {
                saw_upgrade = 1;
            }
        } else if (ci_equal_string_n(name, name_len, "Connection")) {
            if (ci_contains_token(value, value_len, "upgrade")) {
                saw_connection = 1;
            }
        } else if (ci_equal_string_n(name, name_len, "Sec-WebSocket-Version")) {
            if (value_len == 2U && value[0] == '1' && value[1] == '3') {
                saw_version = 1;
            }
        } else if (ci_equal_string_n(name, name_len, "Sec-WebSocket-Key")) {
            if (value_len != 0U && value_len < sizeof(key_copy)) {
                key_value = value;
                key_len = value_len;
                saw_key = 1;
            }
        }

        line_start = line_end + 2U;
    }

    if (!saw_upgrade || !saw_connection || !saw_version || !saw_key) {
        return SOCKIFY_ERR_PROTOCOL;
    }

    for (i = 0; i < key_len; i++) {
        key_copy[i] = key_value[i];
    }
    key_copy[key_len] = '\0';

    rc = sockify_ws_accept_key(key_copy, accept, sizeof(accept));
    if (rc != SOCKIFY_OK) {
        return rc;
    }

    {
        static const char prefix[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ";
        static const char suffix[] = "\r\n\r\n";
        size_t prefix_len;
        size_t suffix_len;
        size_t accept_len;

        prefix_len = sizeof(prefix) - 1U;
        suffix_len = sizeof(suffix) - 1U;
        accept_len = strlen(accept);

        if (prefix_len + accept_len + suffix_len >= sizeof(temp)) {
            return SOCKIFY_ERR_OVERFLOW;
        }
        memcpy(temp, prefix, prefix_len);
        memcpy(temp + prefix_len, accept, accept_len);
        memcpy(temp + prefix_len + accept_len, suffix, suffix_len);
        temp_len = prefix_len + accept_len + suffix_len;
        temp[temp_len] = '\0';
    }

    if (response_size <= temp_len) {
        response[0] = '\0';
        return SOCKIFY_ERR_OVERFLOW;
    }

    memcpy(response, temp, temp_len + 1U);
    *written = temp_len;
    *consumed = header_len;
    return SOCKIFY_OK;
}
