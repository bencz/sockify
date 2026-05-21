#ifndef SOCKIFY_PROXY_H
#define SOCKIFY_PROXY_H

#include "sockify/log.h"
#include "sockify/net.h"

#define SOCKIFY_PATH_MAX 512U

struct sockify_proxy_config {
    struct sockify_endpoint listen_endpoint;
    struct sockify_endpoint target_endpoint;
    size_t max_connections;
    size_t buffer_size;
    size_t accept_budget;
    size_t read_budget;
    size_t write_budget;
    int backlog;
    unsigned int handshake_timeout_ms;
    unsigned int idle_timeout_ms;
    unsigned int connect_timeout_ms;
    enum sockify_log_level log_level;
    int client_tls_enabled;
    char client_tls_cert_file[SOCKIFY_PATH_MAX];
    char client_tls_key_file[SOCKIFY_PATH_MAX];
    char client_tls_pfx_file[SOCKIFY_PATH_MAX];
    char client_tls_pfx_password[256];
    char client_tls_cert_store[128];
    char client_tls_cert_thumbprint[128];
    int target_tls_enabled;
    int target_tls_insecure;
    char target_tls_server_name[256];
    char target_tls_ca_file[SOCKIFY_PATH_MAX];
};

void sockify_proxy_config_init(struct sockify_proxy_config *config);
int sockify_proxy_run(const struct sockify_proxy_config *config);

#endif
