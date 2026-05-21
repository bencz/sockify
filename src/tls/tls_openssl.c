#ifdef SOCKIFY_WITH_OPENSSL

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "sockify/tls.h"

struct sockify_tls_context {
    SSL_CTX *ctx;
    int server_side;
    int verify_peer;
};

struct sockify_tls_connection {
    SSL *ssl;
    int want_read;
    int want_write;
    int server_side;
    int verify_peer;
};

int sockify_tls_is_available(void)
{
    return 1;
}

const char *sockify_tls_backend_name(void)
{
    return "openssl";
}

int sockify_tls_global_init(void)
{
    if (OPENSSL_init_ssl(0, 0) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

void sockify_tls_global_cleanup(void)
{
}

static int context_load_verify_paths(SSL_CTX *ctx, const char *ca_file)
{
    if (ca_file != 0 && ca_file[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, ca_file, 0) != 1) {
            return SOCKIFY_ERR_SYS;
        }
    }
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

static int context_load_server_cert(SSL_CTX *ctx,
                                    const struct sockify_proxy_config *config)
{
    if (config->client_tls_cert_file[0] == '\0' ||
        config->client_tls_key_file[0] == '\0') {
        return SOCKIFY_ERR_UNSUPPORTED;
    }
    if (SSL_CTX_use_certificate_file(ctx,
                                     config->client_tls_cert_file,
                                     SSL_FILETYPE_PEM) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx,
                                    config->client_tls_key_file,
                                    SSL_FILETYPE_PEM) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

int sockify_tls_context_create(const struct sockify_proxy_config *config,
                               int server_side,
                               struct sockify_tls_context **out_context)
{
    const SSL_METHOD *method;
    struct sockify_tls_context *context;
    int rc;

    if (config == 0 || out_context == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    *out_context = 0;

    method = server_side ? TLS_server_method() : TLS_client_method();
    context = (struct sockify_tls_context *)calloc(1U, sizeof(*context));
    if (context == 0) {
        return SOCKIFY_ERR_NOMEM;
    }

    context->ctx = SSL_CTX_new(method);
    if (context->ctx == 0) {
        free(context);
        return SOCKIFY_ERR_SYS;
    }
    context->server_side = server_side ? 1 : 0;
    context->verify_peer = server_side ? 0 : !config->target_tls_insecure;

    SSL_CTX_set_min_proto_version(context->ctx, TLS1_2_VERSION);
#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_CTX_set_options(context->ctx, SSL_OP_NO_RENEGOTIATION);
#endif

    if (server_side) {
        SSL_CTX_set_session_cache_mode(context->ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(context->ctx,
                                       (const unsigned char *)"sockify",
                                       7U);
        rc = context_load_server_cert(context->ctx, config);
        if (rc != SOCKIFY_OK) {
            sockify_tls_context_destroy(context);
            return rc;
        }
    } else {
        if (context->verify_peer) {
            SSL_CTX_set_verify(context->ctx, SSL_VERIFY_PEER, 0);
            rc = context_load_verify_paths(context->ctx, config->target_tls_ca_file);
            if (rc != SOCKIFY_OK) {
                sockify_tls_context_destroy(context);
                return rc;
            }
        } else {
            SSL_CTX_set_verify(context->ctx, SSL_VERIFY_NONE, 0);
        }
    }

    *out_context = context;
    return SOCKIFY_OK;
}

void sockify_tls_context_destroy(struct sockify_tls_context *context)
{
    if (context == 0) {
        return;
    }
    if (context->ctx != 0) {
        SSL_CTX_free(context->ctx);
    }
    free(context);
}

static void connection_clear_wants(struct sockify_tls_connection *connection)
{
    connection->want_read = 0;
    connection->want_write = 0;
}

static int map_ssl_error(struct sockify_tls_connection *connection,
                         int ret,
                         int handshake)
{
    int err;

    connection_clear_wants(connection);
    err = SSL_get_error(connection->ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        connection->want_read = 1;
        return SOCKIFY_ERR_AGAIN;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
        connection->want_write = 1;
        return SOCKIFY_ERR_AGAIN;
    }
    if (err == SSL_ERROR_ZERO_RETURN) {
        return SOCKIFY_ERR_CLOSED;
    }
    if (handshake) {
        return SOCKIFY_ERR_TLS_HANDSHAKE;
    }
    return SOCKIFY_ERR_SYS;
}

static int set_connection_hostname(struct sockify_tls_connection *connection,
                                   const char *server_name)
{
    X509_VERIFY_PARAM *param;

    if (server_name == 0 || server_name[0] == '\0') {
        return SOCKIFY_OK;
    }
    if (SSL_set_tlsext_host_name(connection->ssl, server_name) != 1) {
        return SOCKIFY_ERR_SYS;
    }
    if (connection->verify_peer) {
        param = SSL_get0_param(connection->ssl);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (X509_VERIFY_PARAM_set1_host(param, server_name, 0) != 1) {
            return SOCKIFY_ERR_SYS;
        }
    }
    return SOCKIFY_OK;
}

int sockify_tls_connection_create(struct sockify_tls_context *context,
                                  sockify_socket_t fd,
                                  int server_side,
                                  const char *server_name,
                                  struct sockify_tls_connection **out_connection)
{
    struct sockify_tls_connection *connection;
    int rc;

    if (context == 0 || out_connection == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    *out_connection = 0;
    if ((server_side ? 1 : 0) != context->server_side) {
        return SOCKIFY_ERR_INVALID;
    }

    connection = (struct sockify_tls_connection *)calloc(1U, sizeof(*connection));
    if (connection == 0) {
        return SOCKIFY_ERR_NOMEM;
    }
    connection->ssl = SSL_new(context->ctx);
    if (connection->ssl == 0) {
        free(connection);
        return SOCKIFY_ERR_SYS;
    }
    connection->server_side = server_side ? 1 : 0;
    connection->verify_peer = context->verify_peer;

    if (SSL_set_fd(connection->ssl, fd) != 1) {
        sockify_tls_connection_destroy(connection);
        return SOCKIFY_ERR_SYS;
    }

    if (server_side) {
        SSL_set_accept_state(connection->ssl);
    } else {
        SSL_set_connect_state(connection->ssl);
        rc = set_connection_hostname(connection, server_name);
        if (rc != SOCKIFY_OK) {
            sockify_tls_connection_destroy(connection);
            return rc;
        }
    }

    *out_connection = connection;
    return SOCKIFY_OK;
}

int sockify_tls_connection_handshake(struct sockify_tls_connection *connection)
{
    int ret;
    long verify_result;

    if (connection == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    ret = SSL_do_handshake(connection->ssl);
    if (ret == 1) {
        connection_clear_wants(connection);
        if (!connection->server_side && connection->verify_peer) {
            verify_result = SSL_get_verify_result(connection->ssl);
            if (verify_result != X509_V_OK) {
                return SOCKIFY_ERR_TLS_VERIFY;
            }
        }
        return SOCKIFY_OK;
    }
    return map_ssl_error(connection, ret, 1);
}

int sockify_tls_connection_read(struct sockify_tls_connection *connection,
                                unsigned char *buffer,
                                size_t buffer_size,
                                size_t *read_count)
{
    int ret;

    if (read_count != 0) {
        *read_count = 0;
    }
    if (connection == 0 || buffer == 0 || read_count == 0 ||
        buffer_size > (size_t)INT_MAX) {
        return SOCKIFY_ERR_INVALID;
    }
    ret = SSL_read(connection->ssl, buffer, (int)buffer_size);
    if (ret > 0) {
        connection_clear_wants(connection);
        *read_count = (size_t)ret;
        return SOCKIFY_OK;
    }
    return map_ssl_error(connection, ret, 0);
}

int sockify_tls_connection_write(struct sockify_tls_connection *connection,
                                 const unsigned char *buffer,
                                 size_t buffer_len,
                                 size_t *written)
{
    int ret;

    if (written != 0) {
        *written = 0;
    }
    if (connection == 0 || written == 0 ||
        (buffer_len != 0U && buffer == 0) ||
        buffer_len > (size_t)INT_MAX) {
        return SOCKIFY_ERR_INVALID;
    }
    if (buffer_len == 0U) {
        return SOCKIFY_OK;
    }
    ret = SSL_write(connection->ssl, buffer, (int)buffer_len);
    if (ret > 0) {
        connection_clear_wants(connection);
        *written = (size_t)ret;
        return SOCKIFY_OK;
    }
    return map_ssl_error(connection, ret, 0);
}

int sockify_tls_connection_shutdown(struct sockify_tls_connection *connection)
{
    int ret;

    if (connection == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    ret = SSL_shutdown(connection->ssl);
    if (ret == 1) {
        connection_clear_wants(connection);
        return SOCKIFY_OK;
    }
    if (ret == 0) {
        connection->want_read = 1;
        connection->want_write = 1;
        return SOCKIFY_ERR_AGAIN;
    }
    return map_ssl_error(connection, ret, 0);
}

void sockify_tls_connection_destroy(struct sockify_tls_connection *connection)
{
    if (connection == 0) {
        return;
    }
    if (connection->ssl != 0) {
        SSL_free(connection->ssl);
    }
    free(connection);
}

int sockify_tls_connection_wants_read(const struct sockify_tls_connection *connection)
{
    if (connection == 0) {
        return 0;
    }
    return connection->want_read;
}

int sockify_tls_connection_wants_write(const struct sockify_tls_connection *connection)
{
    if (connection == 0) {
        return 0;
    }
    return connection->want_write;
}

#endif
