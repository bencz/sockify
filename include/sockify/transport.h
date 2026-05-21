#ifndef SOCKIFY_TRANSPORT_H
#define SOCKIFY_TRANSPORT_H

#include "sockify/net.h"

#define SOCKIFY_TRANSPORT_PLAIN 1
#define SOCKIFY_TRANSPORT_TLS 2

struct sockify_tls_connection;
struct sockify_tls_context;

struct sockify_transport {
    int type;
    sockify_socket_t fd;
    struct sockify_tls_connection *tls;
};

int sockify_transport_init_plain(struct sockify_transport *transport,
                                 sockify_socket_t fd);

int sockify_transport_init_tls(struct sockify_transport *transport,
                               sockify_socket_t fd,
                               struct sockify_tls_context *context,
                               int server_side,
                               const char *server_name);

sockify_socket_t sockify_transport_fd(const struct sockify_transport *transport);
int sockify_transport_handshake(struct sockify_transport *transport);
int sockify_transport_read(struct sockify_transport *transport,
                           unsigned char *buffer,
                           size_t buffer_size,
                           size_t *read_count);
int sockify_transport_write(struct sockify_transport *transport,
                            const unsigned char *buffer,
                            size_t buffer_len,
                            size_t *written);
int sockify_transport_shutdown(struct sockify_transport *transport);
void sockify_transport_destroy(struct sockify_transport *transport);
int sockify_transport_wants_read(const struct sockify_transport *transport);
int sockify_transport_wants_write(const struct sockify_transport *transport);

#endif
