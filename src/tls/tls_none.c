#ifndef SOCKIFY_WITH_OPENSSL

#include <stdlib.h>

#include "sockify/tls.h"

struct sockify_tls_context {
    int unused;
};

struct sockify_tls_connection {
    int unused;
};

int sockify_tls_is_available(void)
{
    return 0;
}

const char *sockify_tls_backend_name(void)
{
    return "none";
}

int sockify_tls_global_init(void)
{
    return SOCKIFY_OK;
}

void sockify_tls_global_cleanup(void)
{
}

int sockify_tls_context_create(const struct sockify_proxy_config *config,
                               int server_side,
                               struct sockify_tls_context **out_context)
{
    SOCKIFY_UNUSED(config);
    SOCKIFY_UNUSED(server_side);
    if (out_context != 0) {
        *out_context = 0;
    }
    return SOCKIFY_ERR_UNSUPPORTED;
}

void sockify_tls_context_destroy(struct sockify_tls_context *context)
{
    SOCKIFY_UNUSED(context);
}

int sockify_tls_connection_create(struct sockify_tls_context *context,
                                  sockify_socket_t fd,
                                  int server_side,
                                  const char *server_name,
                                  struct sockify_tls_connection **out_connection)
{
    SOCKIFY_UNUSED(context);
    SOCKIFY_UNUSED(fd);
    SOCKIFY_UNUSED(server_side);
    SOCKIFY_UNUSED(server_name);
    if (out_connection != 0) {
        *out_connection = 0;
    }
    return SOCKIFY_ERR_UNSUPPORTED;
}

int sockify_tls_connection_handshake(struct sockify_tls_connection *connection)
{
    SOCKIFY_UNUSED(connection);
    return SOCKIFY_ERR_UNSUPPORTED;
}

int sockify_tls_connection_read(struct sockify_tls_connection *connection,
                                unsigned char *buffer,
                                size_t buffer_size,
                                size_t *read_count)
{
    SOCKIFY_UNUSED(connection);
    SOCKIFY_UNUSED(buffer);
    SOCKIFY_UNUSED(buffer_size);
    if (read_count != 0) {
        *read_count = 0;
    }
    return SOCKIFY_ERR_UNSUPPORTED;
}

int sockify_tls_connection_write(struct sockify_tls_connection *connection,
                                 const unsigned char *buffer,
                                 size_t buffer_len,
                                 size_t *written)
{
    SOCKIFY_UNUSED(connection);
    SOCKIFY_UNUSED(buffer);
    SOCKIFY_UNUSED(buffer_len);
    if (written != 0) {
        *written = 0;
    }
    return SOCKIFY_ERR_UNSUPPORTED;
}

int sockify_tls_connection_shutdown(struct sockify_tls_connection *connection)
{
    SOCKIFY_UNUSED(connection);
    return SOCKIFY_ERR_UNSUPPORTED;
}

void sockify_tls_connection_destroy(struct sockify_tls_connection *connection)
{
    SOCKIFY_UNUSED(connection);
}

int sockify_tls_connection_wants_read(const struct sockify_tls_connection *connection)
{
    SOCKIFY_UNUSED(connection);
    return 0;
}

int sockify_tls_connection_wants_write(const struct sockify_tls_connection *connection)
{
    SOCKIFY_UNUSED(connection);
    return 0;
}

#endif
