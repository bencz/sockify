#ifndef SOCKIFY_TLS_H
#define SOCKIFY_TLS_H

#include "sockify/net.h"
#include "sockify/proxy.h"

#define SOCKIFY_ERR_TLS_HANDSHAKE -9
#define SOCKIFY_ERR_TLS_VERIFY -10

struct sockify_tls_context;
struct sockify_tls_connection;

int sockify_tls_is_available(void);
const char *sockify_tls_backend_name(void);
int sockify_tls_global_init(void);
void sockify_tls_global_cleanup(void);

int sockify_tls_context_create(const struct sockify_proxy_config *config,
                               int server_side,
                               struct sockify_tls_context **out_context);
void sockify_tls_context_destroy(struct sockify_tls_context *context);

int sockify_tls_connection_create(struct sockify_tls_context *context,
                                  sockify_socket_t fd,
                                  int server_side,
                                  const char *server_name,
                                  struct sockify_tls_connection **out_connection);
int sockify_tls_connection_handshake(struct sockify_tls_connection *connection);
int sockify_tls_connection_read(struct sockify_tls_connection *connection,
                                unsigned char *buffer,
                                size_t buffer_size,
                                size_t *read_count);
int sockify_tls_connection_write(struct sockify_tls_connection *connection,
                                 const unsigned char *buffer,
                                 size_t buffer_len,
                                 size_t *written);
int sockify_tls_connection_shutdown(struct sockify_tls_connection *connection);
void sockify_tls_connection_destroy(struct sockify_tls_connection *connection);
int sockify_tls_connection_wants_read(const struct sockify_tls_connection *connection);
int sockify_tls_connection_wants_write(const struct sockify_tls_connection *connection);

#endif
