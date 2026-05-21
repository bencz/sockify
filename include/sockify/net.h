#ifndef SOCKIFY_NET_H
#define SOCKIFY_NET_H

#include "sockify/core.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sockify_socket_t;
#else
typedef int sockify_socket_t;
#endif

struct sockify_endpoint {
    char host[256];
    char port[16];
};

sockify_socket_t sockify_net_invalid_socket(void);
int sockify_net_init(void);
void sockify_net_cleanup(void);
void sockify_net_close(sockify_socket_t fd);
int sockify_net_set_nonblocking(sockify_socket_t fd);
int sockify_net_set_tcp_nodelay(sockify_socket_t fd);
int sockify_net_would_block(void);
int sockify_net_parse_endpoint(const char *text, struct sockify_endpoint *endpoint);
int sockify_net_listen(const struct sockify_endpoint *endpoint,
                       int backlog,
                       sockify_socket_t *out_fd);
int sockify_net_connect(const struct sockify_endpoint *endpoint,
                        sockify_socket_t *out_fd,
                        int *in_progress);
int sockify_net_accept(sockify_socket_t listener, sockify_socket_t *out_fd);
int sockify_net_recv(sockify_socket_t fd,
                     unsigned char *buffer,
                     size_t buffer_size,
                     size_t *read_count);
int sockify_net_send(sockify_socket_t fd,
                     const unsigned char *buffer,
                     size_t buffer_len,
                     size_t *sent_count);
int sockify_net_socket_error(sockify_socket_t fd, int *socket_error);

#endif
