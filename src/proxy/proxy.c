#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sockify/buffer.h"
#include "sockify/event_loop.h"
#include "sockify/log.h"
#include "sockify/proxy.h"
#include "sockify/tls.h"
#include "sockify/transport.h"
#include "sockify/ws.h"

#define SOCKIFY_PROXY_IO_CHUNK 4096U

#define SESSION_SIDE_CLIENT 1
#define SESSION_SIDE_TARGET 2

struct sockify_proxy_server;

struct sockify_session_side {
    struct sockify_proxy_session *session;
    int side;
};

struct sockify_proxy_session {
    struct sockify_proxy_server *server;
    struct sockify_proxy_session *next;
    struct sockify_proxy_session *prev;
    sockify_socket_t client_fd;
    sockify_socket_t target_fd;
    struct sockify_transport client_transport;
    struct sockify_transport target_transport;
    int client_registered;
    int target_registered;
    int target_connecting;
    int client_tls_ready;
    int target_tls_ready;
    int handshake_done;
    int closing;
    int pending_close;
    unsigned char pending_close_payload[125];
    size_t pending_close_payload_len;
    char handshake[SOCKIFY_WS_MAX_HTTP_REQUEST];
    size_t handshake_len;
    struct sockify_ws_parser ws_parser;
    struct sockify_buffer client_to_target;
    struct sockify_buffer target_to_client;
    unsigned char *client_to_target_storage;
    unsigned char *target_to_client_storage;
    unsigned char *client_out;
    size_t client_out_len;
    size_t client_out_pos;
    size_t client_out_capacity;
    struct sockify_session_side client_side;
    struct sockify_session_side target_side;
    time_t created_at;
    time_t connect_started_at;
    time_t last_activity_at;
};

struct sockify_proxy_server {
    struct sockify_proxy_config config;
    struct sockify_event_loop *loop;
    sockify_socket_t listener_fd;
    struct sockify_tls_context *client_tls_context;
    struct sockify_tls_context *target_tls_context;
    size_t active_connections;
    struct sockify_proxy_session *sessions;
};

static size_t min_size(size_t a, size_t b)
{
    if (a < b) {
        return a;
    }
    return b;
}

void sockify_proxy_config_init(struct sockify_proxy_config *config)
{
    if (config == 0) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->max_connections = 10000U;
    config->buffer_size = SOCKIFY_WS_MAX_FRAME_PAYLOAD;
    config->accept_budget = 64U;
    config->read_budget = 16U;
    config->write_budget = 16U;
    config->backlog = 512;
    config->handshake_timeout_ms = 10000U;
    config->idle_timeout_ms = 300000U;
    config->connect_timeout_ms = 10000U;
    config->log_level = SOCKIFY_LOG_INFO;
}

static void session_update_events(struct sockify_proxy_session *session);

static int tls_enabled(const struct sockify_proxy_config *config)
{
    return config->client_tls_enabled || config->target_tls_enabled;
}

static int transport_tls_event_mask(const struct sockify_transport *transport)
{
    int events;

    events = 0;
    if (sockify_transport_wants_read(transport)) {
        events |= SOCKIFY_EVENT_READ;
    }
    if (sockify_transport_wants_write(transport)) {
        events |= SOCKIFY_EVENT_WRITE;
    }
    if (events == 0) {
        events = SOCKIFY_EVENT_READ | SOCKIFY_EVENT_WRITE;
    }
    return events;
}

static void server_unlink_session(struct sockify_proxy_server *server,
                                  struct sockify_proxy_session *session)
{
    if (session->prev != 0) {
        session->prev->next = session->next;
    } else if (server->sessions == session) {
        server->sessions = session->next;
    } else {
        return;
    }
    if (session->next != 0) {
        session->next->prev = session->prev;
    }
    session->prev = 0;
    session->next = 0;
    if (server->active_connections != 0U) {
        server->active_connections--;
    }
}

static void session_touch(struct sockify_proxy_session *session)
{
    if (session == 0) {
        return;
    }
    session->last_activity_at = time(0);
}

static void session_close(struct sockify_proxy_session *session)
{
    struct sockify_proxy_server *server;

    if (session == 0 || session->closing == 2) {
        return;
    }

    session->closing = 2;
    server = session->server;

    if (session->client_registered) {
        sockify_event_loop_remove(server->loop, session->client_fd);
        session->client_registered = 0;
    }
    if (session->target_registered) {
        sockify_event_loop_remove(server->loop, session->target_fd);
        session->target_registered = 0;
    }
    if (session->client_fd != sockify_net_invalid_socket()) {
        sockify_transport_destroy(&session->client_transport);
        sockify_net_close(session->client_fd);
    }
    if (session->target_fd != sockify_net_invalid_socket()) {
        sockify_transport_destroy(&session->target_transport);
        sockify_net_close(session->target_fd);
    }

    server_unlink_session(server, session);
    free(session->client_to_target_storage);
    free(session->target_to_client_storage);
    free(session->client_out);
    free(session);
}

static int session_set_client_out(struct sockify_proxy_session *session,
                                  const unsigned char *data,
                                  size_t data_len)
{
    if (data_len > session->client_out_capacity) {
        return SOCKIFY_ERR_OVERFLOW;
    }
    if (session->client_out_len != session->client_out_pos) {
        return SOCKIFY_ERR_AGAIN;
    }
    if (data_len != 0U) {
        memcpy(session->client_out, data, data_len);
    }
    session->client_out_len = data_len;
    session->client_out_pos = 0;
    return SOCKIFY_OK;
}

static int session_make_ws_frame(struct sockify_proxy_session *session,
                                 unsigned int opcode,
                                 const unsigned char *payload,
                                 size_t payload_len)
{
    size_t written;
    int rc;

    if (session->client_out_len != session->client_out_pos) {
        return SOCKIFY_ERR_AGAIN;
    }
    written = 0;
    rc = sockify_ws_write_frame(opcode, payload, payload_len,
                                session->client_out,
                                session->client_out_capacity,
                                &written);
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    session->client_out_len = written;
    session->client_out_pos = 0;
    return SOCKIFY_OK;
}

static void session_handle_target_event(struct sockify_proxy_session *session, int events);
static void session_handle_client_event(struct sockify_proxy_session *session, int events);

static void session_event_callback(struct sockify_event_loop *loop,
                                   sockify_socket_t fd,
                                   int events,
                                   void *user_data)
{
    struct sockify_session_side *side;

    SOCKIFY_UNUSED(loop);
    SOCKIFY_UNUSED(fd);

    side = (struct sockify_session_side *)user_data;
    if (side == 0 || side->session == 0) {
        return;
    }
    if (side->side == SESSION_SIDE_CLIENT) {
        session_handle_client_event(side->session, events);
    } else {
        session_handle_target_event(side->session, events);
    }
}

static int session_register_target(struct sockify_proxy_session *session)
{
    int rc;

    if (session->target_registered) {
        return SOCKIFY_OK;
    }
    session->target_side.session = session;
    session->target_side.side = SESSION_SIDE_TARGET;
    rc = sockify_event_loop_add(session->server->loop,
                                session->target_fd,
                                SOCKIFY_EVENT_WRITE,
                                session_event_callback,
                                &session->target_side);
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    session->target_registered = 1;
    return SOCKIFY_OK;
}

static int session_start_target(struct sockify_proxy_session *session)
{
    int in_progress;
    int rc;

    if (session->target_fd != sockify_net_invalid_socket()) {
        return SOCKIFY_OK;
    }

    in_progress = 0;
    rc = sockify_net_connect(&session->server->config.target_endpoint,
                             &session->target_fd,
                             &in_progress);
    if (rc != SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_WARN, "target connect failed");
        return rc;
    }

    sockify_log(SOCKIFY_LOG_DEBUG, "target connect started for %s:%s",
                session->server->config.target_endpoint.host,
                session->server->config.target_endpoint.port);
    session->target_connecting = in_progress;
    session->connect_started_at = time(0);
    rc = sockify_transport_init_plain(&session->target_transport, session->target_fd);
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    return session_register_target(session);
}

static int session_complete_target_connect(struct sockify_proxy_session *session)
{
    int socket_error;
    int rc;
    const char *server_name;

    if (!session->target_connecting) {
        return SOCKIFY_OK;
    }

    socket_error = 0;
    rc = sockify_net_socket_error(session->target_fd, &socket_error);
    if (rc != SOCKIFY_OK || socket_error != 0) {
        sockify_log(SOCKIFY_LOG_WARN, "target connect completion failed");
        return SOCKIFY_ERR_SYS;
    }

    sockify_log(SOCKIFY_LOG_DEBUG, "target connect completed");
    session->target_connecting = 0;
    session->connect_started_at = 0;
    session->last_activity_at = time(0);
    if (session->server->config.target_tls_enabled) {
        sockify_transport_destroy(&session->target_transport);
        server_name = session->server->config.target_tls_server_name;
        if (server_name[0] == '\0') {
            server_name = session->server->config.target_endpoint.host;
        }
        rc = sockify_transport_init_tls(&session->target_transport,
                                        session->target_fd,
                                        session->server->target_tls_context,
                                        0,
                                        server_name);
        if (rc != SOCKIFY_OK) {
            return rc;
        }
        session->target_tls_ready = 0;
    } else {
        session->target_tls_ready = 1;
    }
    return SOCKIFY_OK;
}

static int session_process_ws_bytes(struct sockify_proxy_session *session,
                                    const unsigned char *data,
                                    size_t data_len);

static int session_drive_client_tls(struct sockify_proxy_session *session)
{
    int rc;

    if (session->client_tls_ready) {
        return SOCKIFY_OK;
    }
    rc = sockify_transport_handshake(&session->client_transport);
    if (rc == SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_DEBUG, "client tls handshake completed");
        session->client_tls_ready = 1;
        return SOCKIFY_OK;
    }
    if (rc == SOCKIFY_ERR_AGAIN) {
        return SOCKIFY_ERR_AGAIN;
    }
    sockify_log(SOCKIFY_LOG_WARN, "client tls handshake failed");
    return rc;
}

static int session_drive_target_tls(struct sockify_proxy_session *session)
{
    int rc;

    if (session->target_tls_ready) {
        return SOCKIFY_OK;
    }
    rc = sockify_transport_handshake(&session->target_transport);
    if (rc == SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_DEBUG, "target tls handshake completed");
        session->target_tls_ready = 1;
        return SOCKIFY_OK;
    }
    if (rc == SOCKIFY_ERR_AGAIN) {
        return SOCKIFY_ERR_AGAIN;
    }
    if (rc == SOCKIFY_ERR_TLS_VERIFY) {
        sockify_log(SOCKIFY_LOG_WARN, "target tls verification failed");
    } else {
        sockify_log(SOCKIFY_LOG_WARN, "target tls handshake failed");
    }
    return rc;
}

static void session_handle_handshake_bytes(struct sockify_proxy_session *session,
                                           const unsigned char *data,
                                           size_t data_len)
{
    size_t available;
    size_t written;
    size_t consumed;
    char response[256];
    size_t response_len;
    int rc;

    available = sizeof(session->handshake) - session->handshake_len;
    if (data_len > available) {
        session_close(session);
        return;
    }

    memcpy(session->handshake + session->handshake_len, data, data_len);
    session->handshake_len += data_len;

    response_len = 0;
    consumed = 0;
    rc = sockify_ws_build_handshake_response_ex(session->handshake,
                                                session->handshake_len,
                                                response,
                                                sizeof(response),
                                                &response_len,
                                                &consumed);
    if (rc == SOCKIFY_ERR_AGAIN) {
        return;
    }
    if (rc != SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_WARN, "invalid websocket handshake");
        session_close(session);
        return;
    }

    sockify_log(SOCKIFY_LOG_DEBUG, "websocket handshake accepted");
    written = response_len;
    if (session_set_client_out(session, (const unsigned char *)response, written) != SOCKIFY_OK) {
        session_close(session);
        return;
    }

    session->handshake_done = 1;
    if (session_start_target(session) != SOCKIFY_OK) {
        session_close(session);
        return;
    }
    if (consumed < session->handshake_len) {
        rc = session_process_ws_bytes(session,
                                      (const unsigned char *)session->handshake + consumed,
                                      session->handshake_len - consumed);
        if (rc != SOCKIFY_OK && rc != SOCKIFY_ERR_AGAIN) {
            session_close(session);
            return;
        }
    }
    session->handshake_len = 0;
}

static void session_handle_ws_message(struct sockify_proxy_session *session,
                                      const struct sockify_ws_message *msg)
{
    size_t written;
    int rc;

    if (msg->opcode == SOCKIFY_WS_OPCODE_BINARY ||
        msg->opcode == SOCKIFY_WS_OPCODE_TEXT ||
        msg->opcode == SOCKIFY_WS_OPCODE_CONTINUATION) {
        written = 0;
        rc = sockify_buffer_write(&session->client_to_target,
                                  msg->payload,
                                  msg->payload_len,
                                  &written);
        if (rc != SOCKIFY_OK || written != msg->payload_len) {
            session_close(session);
            return;
        }
    } else if (msg->opcode == SOCKIFY_WS_OPCODE_PING) {
        if (session_make_ws_frame(session,
                                  SOCKIFY_WS_OPCODE_PONG,
                                  msg->payload,
                                  msg->payload_len) != SOCKIFY_OK) {
            session_close(session);
            return;
        }
    } else if (msg->opcode == SOCKIFY_WS_OPCODE_CLOSE) {
        size_t close_len;

        session->closing = 1;
        close_len = msg->payload_len;
        if (close_len > sizeof(session->pending_close_payload)) {
            close_len = sizeof(session->pending_close_payload);
        }
        if (close_len != 0U) {
            memcpy(session->pending_close_payload, msg->payload, close_len);
        }
        session->pending_close_payload_len = close_len;
        session->pending_close = 1;
        if (session->client_out_len == session->client_out_pos) {
            if (session_make_ws_frame(session,
                                      SOCKIFY_WS_OPCODE_CLOSE,
                                      session->pending_close_payload,
                                      session->pending_close_payload_len) == SOCKIFY_OK) {
                session->pending_close = 0;
            }
        }
    }
}

static int session_process_ws_bytes(struct sockify_proxy_session *session,
                                    const unsigned char *data,
                                    size_t data_len)
{
    unsigned char ws_payload[SOCKIFY_PROXY_IO_CHUNK];
    struct sockify_ws_message msg;
    size_t offset;
    size_t used;
    size_t payload_capacity;
    int rc;

    offset = 0;
    while (offset < data_len && !session->closing) {
        payload_capacity = min_size(sizeof(ws_payload),
                                    sockify_buffer_writable(&session->client_to_target));
        if (payload_capacity == 0U) {
            return SOCKIFY_ERR_AGAIN;
        }
        used = 0;
        rc = sockify_ws_parser_feed(&session->ws_parser,
                                    data + offset,
                                    data_len - offset,
                                    &used,
                                    ws_payload,
                                    payload_capacity,
                                    &msg);
        offset += used;
        if (rc == SOCKIFY_OK) {
            session_handle_ws_message(session, &msg);
        } else if (rc == SOCKIFY_ERR_AGAIN) {
            if (used == 0U) {
                break;
            }
        } else {
            return rc;
        }
    }

    if (session->closing == 2) {
        return SOCKIFY_ERR_CLOSED;
    }
    return SOCKIFY_OK;
}

static void session_read_client(struct sockify_proxy_session *session)
{
    unsigned char buffer[SOCKIFY_PROXY_IO_CHUNK];
    size_t read_limit;
    size_t read_count;
    int rc;
    size_t read_ops;

    read_ops = 0;
    while (!session->closing && read_ops < session->server->config.read_budget) {
        read_limit = sizeof(buffer);
        if (session->handshake_done) {
            read_limit = min_size(read_limit,
                                  sockify_buffer_writable(&session->client_to_target));
            if (read_limit == 0U) {
                return;
            }
        }
        read_count = 0;
        rc = sockify_transport_read(&session->client_transport,
                                    buffer,
                                    read_limit,
                                    &read_count);
        if (rc == SOCKIFY_ERR_AGAIN) {
            return;
        }
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        read_ops++;
        session_touch(session);

        if (!session->handshake_done) {
            session_handle_handshake_bytes(session, buffer, read_count);
            if (!session->handshake_done || session->closing == 2) {
                return;
            }
        } else {
            rc = session_process_ws_bytes(session, buffer, read_count);
            if (rc != SOCKIFY_OK && rc != SOCKIFY_ERR_AGAIN) {
                session_close(session);
                return;
            }
        }

        if (sockify_buffer_is_high(&session->client_to_target)) {
            return;
        }
    }
}

static void session_write_client(struct sockify_proxy_session *session)
{
    unsigned char payload[SOCKIFY_PROXY_IO_CHUNK];
    size_t payload_len;
    size_t sent;
    int rc;
    size_t write_ops;

    write_ops = 0;
    while (session->client_out_pos < session->client_out_len &&
           write_ops < session->server->config.write_budget) {
        sent = 0;
        rc = sockify_transport_write(&session->client_transport,
                                     session->client_out + session->client_out_pos,
                                     session->client_out_len - session->client_out_pos,
                                     &sent);
        if (rc == SOCKIFY_ERR_AGAIN) {
            return;
        }
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        session->client_out_pos += sent;
        write_ops++;
        if (sent != 0U) {
            session_touch(session);
        }
        sockify_log(SOCKIFY_LOG_DEBUG, "sent %lu bytes to websocket client", (unsigned long)sent);
    }

    if (session->client_out_pos < session->client_out_len) {
        return;
    }

    session->client_out_len = 0;
    session->client_out_pos = 0;

    if (session->pending_close) {
        if (session_make_ws_frame(session,
                                  SOCKIFY_WS_OPCODE_CLOSE,
                                  session->pending_close_payload,
                                  session->pending_close_payload_len) == SOCKIFY_OK) {
            session->pending_close = 0;
        }
        return;
    }

    if (session->closing) {
        session_close(session);
        return;
    }

    if (session->handshake_done &&
        sockify_buffer_readable(&session->target_to_client) != 0U) {
        payload_len = min_size(sizeof(payload),
                               sockify_buffer_readable(&session->target_to_client));
        rc = sockify_buffer_read(&session->target_to_client,
                                 payload,
                                 payload_len,
                                 &payload_len);
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        rc = session_make_ws_frame(session,
                                   SOCKIFY_WS_OPCODE_BINARY,
                                   payload,
                                   payload_len);
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
    }
}

static void session_read_target(struct sockify_proxy_session *session)
{
    unsigned char buffer[SOCKIFY_PROXY_IO_CHUNK];
    size_t read_count;
    size_t written;
    int rc;
    size_t read_ops;

    read_ops = 0;
    while (!sockify_buffer_is_high(&session->target_to_client) &&
           read_ops < session->server->config.read_budget) {
        read_count = 0;
        rc = sockify_transport_read(&session->target_transport,
                                    buffer,
                                    sizeof(buffer),
                                    &read_count);
        if (rc == SOCKIFY_ERR_AGAIN) {
            return;
        }
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        read_ops++;
        session_touch(session);
        written = 0;
        rc = sockify_buffer_write(&session->target_to_client,
                                  buffer,
                                  read_count,
                                  &written);
        if (rc != SOCKIFY_OK || written != read_count) {
            session_close(session);
            return;
        }
    }
}

static void session_write_target(struct sockify_proxy_session *session)
{
    unsigned char buffer[SOCKIFY_PROXY_IO_CHUNK];
    size_t count;
    size_t sent;
    int rc;
    size_t write_ops;

    write_ops = 0;
    while (sockify_buffer_readable(&session->client_to_target) != 0U &&
           write_ops < session->server->config.write_budget) {
        count = min_size(sizeof(buffer), sockify_buffer_readable(&session->client_to_target));
        rc = sockify_buffer_peek(&session->client_to_target, buffer, count, &count);
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        sent = 0;
        rc = sockify_transport_write(&session->target_transport, buffer, count, &sent);
        if (rc == SOCKIFY_ERR_AGAIN) {
            return;
        }
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
        write_ops++;
        if (sent != 0U) {
            session_touch(session);
        }
        rc = sockify_buffer_consume(&session->client_to_target, sent, &count);
        if (rc != SOCKIFY_OK) {
            session_close(session);
            return;
        }
    }
}

static void session_update_events(struct sockify_proxy_session *session)
{
    int client_events;
    int target_events;

    if (session == 0 || session->closing == 2) {
        return;
    }

    client_events = 0;
    if (!session->client_tls_ready) {
        client_events |= transport_tls_event_mask(&session->client_transport);
    } else if (!session->closing &&
        (!session->handshake_done ||
         !sockify_buffer_is_high(&session->client_to_target))) {
        client_events |= SOCKIFY_EVENT_READ;
    }
    if (session->client_out_pos < session->client_out_len ||
        sockify_buffer_readable(&session->target_to_client) != 0U) {
        client_events |= SOCKIFY_EVENT_WRITE;
    }
    if (session->client_registered) {
        sockify_event_loop_modify(session->server->loop, session->client_fd, client_events);
    }

    if (session->target_registered) {
        target_events = 0;
        if (session->target_connecting) {
            target_events |= SOCKIFY_EVENT_WRITE;
        } else if (!session->target_tls_ready) {
            target_events |= transport_tls_event_mask(&session->target_transport);
        } else if (!session->target_connecting &&
            !sockify_buffer_is_high(&session->target_to_client)) {
            target_events |= SOCKIFY_EVENT_READ;
        }
        if (session->target_tls_ready &&
            sockify_buffer_readable(&session->client_to_target) != 0U) {
            target_events |= SOCKIFY_EVENT_WRITE;
        }
        sockify_event_loop_modify(session->server->loop, session->target_fd, target_events);
    }
}

static void session_handle_client_event(struct sockify_proxy_session *session, int events)
{
    if ((events & SOCKIFY_EVENT_ERROR) != 0) {
        session_close(session);
        return;
    }
    if (!session->client_tls_ready) {
        if (session_drive_client_tls(session) == SOCKIFY_ERR_AGAIN) {
            session_update_events(session);
            return;
        }
        if (!session->client_tls_ready) {
            session_close(session);
            return;
        }
    }
    if ((events & SOCKIFY_EVENT_READ) != 0) {
        session_read_client(session);
        if (session->closing == 2) return;
    }
    if ((events & SOCKIFY_EVENT_WRITE) != 0) {
        session_write_client(session);
        if (session->closing == 2) return;
    }
    session_update_events(session);
}

static void session_handle_target_event(struct sockify_proxy_session *session, int events)
{
    if ((events & SOCKIFY_EVENT_ERROR) != 0) {
        session_close(session);
        return;
    }
    if (session->target_connecting &&
        (events & SOCKIFY_EVENT_WRITE) != 0) {
        if (session_complete_target_connect(session) != SOCKIFY_OK) {
            session_close(session);
            return;
        }
    }
    if (!session->target_connecting && !session->target_tls_ready) {
        if (session_drive_target_tls(session) == SOCKIFY_ERR_AGAIN) {
            session_update_events(session);
            return;
        }
        if (!session->target_tls_ready) {
            session_close(session);
            return;
        }
    }
    if ((events & SOCKIFY_EVENT_READ) != 0) {
        session_read_target(session);
        if (session->closing == 2) return;
    }
    if ((events & SOCKIFY_EVENT_WRITE) != 0) {
        session_write_target(session);
        if (session->closing == 2) return;
    }
    session_update_events(session);
}

static struct sockify_proxy_session *session_create(struct sockify_proxy_server *server,
                                                    sockify_socket_t client_fd)
{
    struct sockify_proxy_session *session;
    size_t buffer_size;
    int rc;

    buffer_size = server->config.buffer_size;
    if (buffer_size == 0U || buffer_size > SOCKIFY_WS_MAX_FRAME_PAYLOAD) {
        buffer_size = SOCKIFY_WS_MAX_FRAME_PAYLOAD;
    }

    session = (struct sockify_proxy_session *)calloc(1U, sizeof(struct sockify_proxy_session));
    if (session == 0) {
        return 0;
    }

    session->server = server;
    session->client_fd = client_fd;
    session->target_fd = sockify_net_invalid_socket();
    if (server->config.client_tls_enabled) {
        if (sockify_transport_init_tls(&session->client_transport,
                                       client_fd,
                                       server->client_tls_context,
                                       1,
                                       0) != SOCKIFY_OK) {
            session_close(session);
            return 0;
        }
        session->client_tls_ready = 0;
    } else {
        sockify_transport_init_plain(&session->client_transport, client_fd);
        session->client_tls_ready = 1;
    }
    sockify_transport_init_plain(&session->target_transport, sockify_net_invalid_socket());
    session->target_tls_ready = server->config.target_tls_enabled ? 0 : 1;
    session->client_out_capacity = SOCKIFY_PROXY_IO_CHUNK + 14U;
    session->client_to_target_storage = (unsigned char *)malloc(buffer_size);
    session->target_to_client_storage = (unsigned char *)malloc(buffer_size);
    session->client_out = (unsigned char *)malloc(session->client_out_capacity);
    if (session->client_to_target_storage == 0 ||
        session->target_to_client_storage == 0 ||
        session->client_out == 0) {
        session_close(session);
        return 0;
    }

    sockify_buffer_init(&session->client_to_target,
                        session->client_to_target_storage,
                        buffer_size,
                        (buffer_size * 3U) / 4U,
                        buffer_size / 4U);
    sockify_buffer_init(&session->target_to_client,
                        session->target_to_client_storage,
                        buffer_size,
                        (buffer_size * 3U) / 4U,
                        buffer_size / 4U);
    sockify_ws_parser_init(&session->ws_parser);

    session->client_side.session = session;
    session->client_side.side = SESSION_SIDE_CLIENT;
    rc = sockify_event_loop_add(server->loop,
                                client_fd,
                                server->config.client_tls_enabled ?
                                    (SOCKIFY_EVENT_READ | SOCKIFY_EVENT_WRITE) :
                                    SOCKIFY_EVENT_READ,
                                session_event_callback,
                                &session->client_side);
    if (rc != SOCKIFY_OK) {
        session_close(session);
        return 0;
    }
    session->client_registered = 1;
    session->next = server->sessions;
    session->prev = 0;
    if (server->sessions != 0) {
        server->sessions->prev = session;
    }
    server->sessions = session;
    server->active_connections++;
    session->created_at = time(0);
    session->last_activity_at = session->created_at;
    session->connect_started_at = 0;
    return session;
}

static void listener_callback(struct sockify_event_loop *loop,
                              sockify_socket_t fd,
                              int events,
                              void *user_data)
{
    struct sockify_proxy_server *server;
    sockify_socket_t client_fd;
    int rc;
    size_t accepted;

    SOCKIFY_UNUSED(loop);

    server = (struct sockify_proxy_server *)user_data;
    if (server == 0 || (events & SOCKIFY_EVENT_READ) == 0) {
        return;
    }

    accepted = 0;
    while (accepted < server->config.accept_budget) {
        client_fd = sockify_net_invalid_socket();
        rc = sockify_net_accept(fd, &client_fd);
        if (rc == SOCKIFY_ERR_AGAIN) {
            return;
        }
        if (rc != SOCKIFY_OK) {
            sockify_log(SOCKIFY_LOG_WARN, "accept failed");
            return;
        }
        if (server->active_connections >= server->config.max_connections) {
            sockify_log(SOCKIFY_LOG_WARN, "max connections reached");
            sockify_net_close(client_fd);
            accepted++;
            continue;
        }
        sockify_log(SOCKIFY_LOG_DEBUG, "accepted websocket client");
        if (session_create(server, client_fd) == 0) {
            return;
        }
        accepted++;
    }
}

static int session_is_expired(const struct sockify_proxy_session *session,
                              const struct sockify_proxy_config *config,
                              time_t now)
{
    double elapsed_ms;

    if (session->target_connecting && config->connect_timeout_ms != 0U &&
        session->connect_started_at != 0) {
        elapsed_ms = difftime(now, session->connect_started_at) * 1000.0;
        if (elapsed_ms >= (double)config->connect_timeout_ms) {
            return 1;
        }
    }
    if (!session->handshake_done && config->handshake_timeout_ms != 0U) {
        elapsed_ms = difftime(now, session->created_at) * 1000.0;
        if (elapsed_ms >= (double)config->handshake_timeout_ms) {
            return 1;
        }
    }
    if (session->handshake_done && config->idle_timeout_ms != 0U) {
        elapsed_ms = difftime(now, session->last_activity_at) * 1000.0;
        if (elapsed_ms >= (double)config->idle_timeout_ms) {
            return 1;
        }
    }
    return 0;
}

static void proxy_tick(struct sockify_event_loop *loop, void *user_data)
{
    struct sockify_proxy_server *server;
    struct sockify_proxy_session *session;
    struct sockify_proxy_session *next;
    time_t now;

    SOCKIFY_UNUSED(loop);
    server = (struct sockify_proxy_server *)user_data;
    if (server == 0 || server->sessions == 0) {
        return;
    }
    if (server->config.handshake_timeout_ms == 0U &&
        server->config.idle_timeout_ms == 0U &&
        server->config.connect_timeout_ms == 0U) {
        return;
    }

    now = time(0);
    session = server->sessions;
    while (session != 0) {
        next = session->next;
        if (session_is_expired(session, &server->config, now)) {
            sockify_log(SOCKIFY_LOG_INFO, "closing session due to timeout");
            session_close(session);
        }
        session = next;
    }
}

static int proxy_validate_config(const struct sockify_proxy_config *config)
{
    if (config == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    if (config->listen_endpoint.host[0] == '\0' ||
        config->listen_endpoint.port[0] == '\0' ||
        config->target_endpoint.host[0] == '\0' ||
        config->target_endpoint.port[0] == '\0') {
        return SOCKIFY_ERR_INVALID;
    }
    if (config->max_connections == 0U ||
        config->buffer_size == 0U ||
        config->accept_budget == 0U ||
        config->read_budget == 0U ||
        config->write_budget == 0U) {
        return SOCKIFY_ERR_INVALID;
    }
    if (!config->client_tls_enabled &&
        (config->client_tls_cert_file[0] != '\0' ||
         config->client_tls_key_file[0] != '\0' ||
         config->client_tls_pfx_file[0] != '\0' ||
         config->client_tls_cert_store[0] != '\0' ||
         config->client_tls_cert_thumbprint[0] != '\0')) {
        return SOCKIFY_ERR_INVALID;
    }
    if (!config->target_tls_enabled &&
        (config->target_tls_insecure ||
         config->target_tls_server_name[0] != '\0' ||
         config->target_tls_ca_file[0] != '\0')) {
        return SOCKIFY_ERR_INVALID;
    }
    return SOCKIFY_OK;
}

static void proxy_destroy_tls(struct sockify_proxy_server *server)
{
    if (server->client_tls_context != 0) {
        sockify_tls_context_destroy(server->client_tls_context);
        server->client_tls_context = 0;
    }
    if (server->target_tls_context != 0) {
        sockify_tls_context_destroy(server->target_tls_context);
        server->target_tls_context = 0;
    }
    if (tls_enabled(&server->config)) {
        sockify_tls_global_cleanup();
    }
}

static int proxy_init_tls(struct sockify_proxy_server *server)
{
    int rc;

    if (!tls_enabled(&server->config)) {
        return SOCKIFY_OK;
    }
    rc = sockify_tls_global_init();
    if (rc != SOCKIFY_OK) {
        return rc;
    }
    if (!sockify_tls_is_available()) {
        proxy_destroy_tls(server);
        return SOCKIFY_ERR_UNSUPPORTED;
    }
    if (server->config.target_tls_insecure) {
        sockify_log(SOCKIFY_LOG_WARN,
                    "target tls certificate verification is disabled");
    }
    if (server->config.client_tls_enabled) {
        rc = sockify_tls_context_create(&server->config,
                                        1,
                                        &server->client_tls_context);
        if (rc != SOCKIFY_OK) {
            proxy_destroy_tls(server);
            return rc;
        }
    }
    if (server->config.target_tls_enabled) {
        rc = sockify_tls_context_create(&server->config,
                                        0,
                                        &server->target_tls_context);
        if (rc != SOCKIFY_OK) {
            proxy_destroy_tls(server);
            return rc;
        }
    }
    sockify_log(SOCKIFY_LOG_INFO, "tls backend: %s", sockify_tls_backend_name());
    return SOCKIFY_OK;
}

int sockify_proxy_run(const struct sockify_proxy_config *config)
{
    struct sockify_proxy_server server;
    int rc;

    rc = proxy_validate_config(config);
    if (rc != SOCKIFY_OK) {
        return rc;
    }

    memset(&server, 0, sizeof(server));
    server.config = *config;
    server.listener_fd = sockify_net_invalid_socket();

    sockify_log_set_level(config->log_level);

    rc = sockify_net_init();
    if (rc != SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_ERROR, "network initialization failed");
        return rc;
    }

    rc = proxy_init_tls(&server);
    if (rc != SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_ERROR, "tls initialization failed");
        sockify_net_cleanup();
        return rc;
    }

    rc = sockify_net_listen(&server.config.listen_endpoint,
                            server.config.backlog,
                            &server.listener_fd);
    if (rc != SOCKIFY_OK) {
        sockify_log(SOCKIFY_LOG_ERROR, "listen failed on %s:%s",
                    server.config.listen_endpoint.host,
                    server.config.listen_endpoint.port);
        proxy_destroy_tls(&server);
        sockify_net_cleanup();
        return rc;
    }

    server.loop = sockify_event_loop_create();
    if (server.loop == 0) {
        sockify_log(SOCKIFY_LOG_ERROR, "event loop creation failed");
        sockify_net_close(server.listener_fd);
        proxy_destroy_tls(&server);
        sockify_net_cleanup();
        return SOCKIFY_ERR_NOMEM;
    }

    rc = sockify_event_loop_add(server.loop,
                                server.listener_fd,
                                SOCKIFY_EVENT_READ,
                                listener_callback,
                                &server);
    if (rc == SOCKIFY_OK) {
        sockify_event_loop_set_tick(server.loop, proxy_tick, &server);
        sockify_log(SOCKIFY_LOG_INFO, "listening on %s:%s",
                    server.config.listen_endpoint.host,
                    server.config.listen_endpoint.port);
        rc = sockify_event_loop_run(server.loop);
    } else {
        sockify_log(SOCKIFY_LOG_ERROR, "listener event registration failed");
    }

    while (server.sessions != 0) {
        session_close(server.sessions);
    }
    sockify_event_loop_destroy(server.loop);
    sockify_net_close(server.listener_fd);
    proxy_destroy_tls(&server);
    sockify_net_cleanup();
    return rc;
}
