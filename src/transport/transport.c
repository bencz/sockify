#include <string.h>

#include "sockify/core.h"
#include "sockify/tls.h"
#include "sockify/transport.h"

int sockify_transport_init_plain(struct sockify_transport *transport,
                                 sockify_socket_t fd)
{
    if (transport == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    memset(transport, 0, sizeof(*transport));
    transport->type = SOCKIFY_TRANSPORT_PLAIN;
    transport->fd = fd;
    transport->tls = 0;
    return SOCKIFY_OK;
}

int sockify_transport_init_tls(struct sockify_transport *transport,
                               sockify_socket_t fd,
                               struct sockify_tls_context *context,
                               int server_side,
                               const char *server_name)
{
    int rc;

    if (transport == 0 || context == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    memset(transport, 0, sizeof(*transport));
    transport->type = SOCKIFY_TRANSPORT_TLS;
    transport->fd = fd;
    transport->tls = 0;

    rc = sockify_tls_connection_create(context,
                                       fd,
                                       server_side,
                                       server_name,
                                       &transport->tls);
    if (rc != SOCKIFY_OK) {
        memset(transport, 0, sizeof(*transport));
        transport->fd = sockify_net_invalid_socket();
        return rc;
    }
    return SOCKIFY_OK;
}

sockify_socket_t sockify_transport_fd(const struct sockify_transport *transport)
{
    if (transport == 0) {
        return sockify_net_invalid_socket();
    }
    return transport->fd;
}

int sockify_transport_handshake(struct sockify_transport *transport)
{
    if (transport == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return SOCKIFY_OK;
    }
    return sockify_tls_connection_handshake(transport->tls);
}

int sockify_transport_read(struct sockify_transport *transport,
                           unsigned char *buffer,
                           size_t buffer_size,
                           size_t *read_count)
{
    if (transport == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return sockify_net_recv(transport->fd, buffer, buffer_size, read_count);
    }
    return sockify_tls_connection_read(transport->tls, buffer, buffer_size, read_count);
}

int sockify_transport_write(struct sockify_transport *transport,
                            const unsigned char *buffer,
                            size_t buffer_len,
                            size_t *written)
{
    if (transport == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return sockify_net_send(transport->fd, buffer, buffer_len, written);
    }
    return sockify_tls_connection_write(transport->tls, buffer, buffer_len, written);
}

int sockify_transport_shutdown(struct sockify_transport *transport)
{
    if (transport == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return SOCKIFY_OK;
    }
    return sockify_tls_connection_shutdown(transport->tls);
}

void sockify_transport_destroy(struct sockify_transport *transport)
{
    if (transport == 0) {
        return;
    }
    if (transport->type == SOCKIFY_TRANSPORT_TLS && transport->tls != 0) {
        sockify_tls_connection_destroy(transport->tls);
    }
    transport->type = 0;
    transport->fd = sockify_net_invalid_socket();
    transport->tls = 0;
}

int sockify_transport_wants_read(const struct sockify_transport *transport)
{
    if (transport == 0 || transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return 0;
    }
    return sockify_tls_connection_wants_read(transport->tls);
}

int sockify_transport_wants_write(const struct sockify_transport *transport)
{
    if (transport == 0 || transport->type == SOCKIFY_TRANSPORT_PLAIN) {
        return 0;
    }
    return sockify_tls_connection_wants_write(transport->tls);
}
