#ifndef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sockify/net.h"

sockify_socket_t sockify_net_invalid_socket(void)
{
    return -1;
}

int sockify_net_init(void)
{
    signal(SIGPIPE, SIG_IGN);
    return SOCKIFY_OK;
}

void sockify_net_cleanup(void)
{
}

void sockify_net_close(sockify_socket_t fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

int sockify_net_set_nonblocking(sockify_socket_t fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return SOCKIFY_ERR_SYS;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

int sockify_net_set_tcp_nodelay(sockify_socket_t fd)
{
    int yes;

    yes = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(yes)) != 0) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

int sockify_net_would_block(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
}

static int copy_part(char *dst, size_t dst_size, const char *src, size_t src_len)
{
    if (dst == 0 || dst_size == 0U || src_len >= dst_size) {
        return SOCKIFY_ERR_OVERFLOW;
    }
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return SOCKIFY_OK;
}

int sockify_net_parse_endpoint(const char *text, struct sockify_endpoint *endpoint)
{
    const char *colon;
    const char *end_bracket;
    size_t host_len;
    size_t port_len;

    if (text == 0 || endpoint == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    if (text[0] == '[') {
        end_bracket = strchr(text, ']');
        if (end_bracket == 0 || end_bracket[1] != ':') {
            return SOCKIFY_ERR_INVALID;
        }
        host_len = (size_t)(end_bracket - text - 1);
        port_len = strlen(end_bracket + 2);
        if (copy_part(endpoint->host, sizeof(endpoint->host), text + 1, host_len) != SOCKIFY_OK) {
            return SOCKIFY_ERR_OVERFLOW;
        }
        return copy_part(endpoint->port, sizeof(endpoint->port), end_bracket + 2, port_len);
    }

    colon = strrchr(text, ':');
    if (colon == 0 || colon == text || colon[1] == '\0') {
        return SOCKIFY_ERR_INVALID;
    }

    host_len = (size_t)(colon - text);
    port_len = strlen(colon + 1);
    if (copy_part(endpoint->host, sizeof(endpoint->host), text, host_len) != SOCKIFY_OK) {
        return SOCKIFY_ERR_OVERFLOW;
    }
    return copy_part(endpoint->port, sizeof(endpoint->port), colon + 1, port_len);
}

int sockify_net_listen(const struct sockify_endpoint *endpoint,
                       int backlog,
                       sockify_socket_t *out_fd)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *ai;
    int rc;
    int yes;
    sockify_socket_t fd;

    if (endpoint == 0 || out_fd == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    *out_fd = sockify_net_invalid_socket();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(endpoint->host, endpoint->port, &hints, &result);
    if (rc != 0) {
        return SOCKIFY_ERR_SYS;
    }

    yes = 1;
    for (ai = result; ai != 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) != 0) {
            close(fd);
            continue;
        }
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0 &&
            sockify_net_set_nonblocking(fd) == SOCKIFY_OK) {
            *out_fd = fd;
            freeaddrinfo(result);
            return SOCKIFY_OK;
        }
        close(fd);
    }

    freeaddrinfo(result);
    return SOCKIFY_ERR_SYS;
}

int sockify_net_connect(const struct sockify_endpoint *endpoint,
                        sockify_socket_t *out_fd,
                        int *in_progress)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *ai;
    int rc;
    sockify_socket_t fd;

    if (endpoint == 0 || out_fd == 0 || in_progress == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    *out_fd = sockify_net_invalid_socket();
    *in_progress = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(endpoint->host, endpoint->port, &hints, &result);
    if (rc != 0) {
        return SOCKIFY_ERR_SYS;
    }

    for (ai = result; ai != 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (sockify_net_set_nonblocking(fd) != SOCKIFY_OK) {
            close(fd);
            continue;
        }
        sockify_net_set_tcp_nodelay(fd);
        rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0 || errno == EINPROGRESS) {
            *out_fd = fd;
            *in_progress = (rc != 0);
            freeaddrinfo(result);
            return SOCKIFY_OK;
        }
        close(fd);
    }

    freeaddrinfo(result);
    return SOCKIFY_ERR_SYS;
}

int sockify_net_accept(sockify_socket_t listener, sockify_socket_t *out_fd)
{
    sockify_socket_t fd;

    if (out_fd == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    *out_fd = sockify_net_invalid_socket();

#if defined(__linux__) && defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    fd = accept4(listener, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
        if (sockify_net_would_block()) {
            return SOCKIFY_ERR_AGAIN;
        }
        return SOCKIFY_ERR_SYS;
    }
#else
    fd = accept(listener, 0, 0);
    if (fd < 0) {
        if (sockify_net_would_block()) {
            return SOCKIFY_ERR_AGAIN;
        }
        return SOCKIFY_ERR_SYS;
    }
    if (sockify_net_set_nonblocking(fd) != SOCKIFY_OK) {
        close(fd);
        return SOCKIFY_ERR_SYS;
    }
#endif
    sockify_net_set_tcp_nodelay(fd);
    *out_fd = fd;
    return SOCKIFY_OK;
}

int sockify_net_recv(sockify_socket_t fd,
                     unsigned char *buffer,
                     size_t buffer_size,
                     size_t *read_count)
{
    ssize_t n;

    if (read_count != 0) {
        *read_count = 0;
    }
    if (buffer == 0 || read_count == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    n = recv(fd, buffer, buffer_size, 0);
    if (n > 0) {
        *read_count = (size_t)n;
        return SOCKIFY_OK;
    }
    if (n == 0) {
        return SOCKIFY_ERR_CLOSED;
    }
    if (sockify_net_would_block()) {
        return SOCKIFY_ERR_AGAIN;
    }
    return SOCKIFY_ERR_SYS;
}

int sockify_net_send(sockify_socket_t fd,
                     const unsigned char *buffer,
                     size_t buffer_len,
                     size_t *sent_count)
{
    ssize_t n;

    if (sent_count != 0) {
        *sent_count = 0;
    }
    if ((buffer_len != 0U && buffer == 0) || sent_count == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (buffer_len == 0U) {
        return SOCKIFY_OK;
    }

    n = send(fd, buffer, buffer_len, 0);
    if (n > 0) {
        *sent_count = (size_t)n;
        return SOCKIFY_OK;
    }
    if (n == 0 || sockify_net_would_block()) {
        return SOCKIFY_ERR_AGAIN;
    }
    return SOCKIFY_ERR_SYS;
}

int sockify_net_socket_error(sockify_socket_t fd, int *socket_error)
{
    socklen_t len;
    int err;

    if (socket_error == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    err = 0;
    len = (socklen_t)sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != 0) {
        return SOCKIFY_ERR_SYS;
    }
    *socket_error = err;
    return SOCKIFY_OK;
}

#endif
