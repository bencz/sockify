#include "sockify/cli.h"

#include <stdlib.h>
#include <string.h>

#include "sockify/core.h"
#include "sockify/net.h"

void sockify_cli_print_usage(FILE *out)
{
    if (out == 0) {
        return;
    }
    fprintf(out, "Usage: sockify [options] LISTEN TARGET\n\n");
    fprintf(out, "  LISTEN   host:port to accept WebSocket clients on\n");
    fprintf(out, "  TARGET   host:port of the plain TCP service to forward to\n\n");
    fprintf(out, "Options:\n");
    fprintf(out, "  --help\n");
    fprintf(out, "  --version\n");
    fprintf(out, "  --max-connections N\n");
    fprintf(out, "  --buffer-size N\n");
    fprintf(out, "  --handshake-timeout MS\n");
    fprintf(out, "  --idle-timeout MS\n");
    fprintf(out, "  --connect-timeout MS\n");
    fprintf(out, "  --log-level error|warn|info|debug\n");
    fprintf(out, "  --client-tls\n");
    fprintf(out, "  --client-tls-cert FILE\n");
    fprintf(out, "  --client-tls-key FILE\n");
    fprintf(out, "  --client-tls-pfx FILE\n");
    fprintf(out, "  --client-tls-pfx-password PASS\n");
    fprintf(out, "  --client-tls-cert-store STORE\n");
    fprintf(out, "  --client-tls-cert-thumbprint HEX\n");
    fprintf(out, "  --target-tls\n");
    fprintf(out, "  --target-tls-server-name NAME\n");
    fprintf(out, "  --target-tls-ca-file FILE\n");
    fprintf(out, "  --target-tls-insecure\n");
}

static int copy_str(char *dest, size_t dest_size, const char *src)
{
    size_t len;

    len = strlen(src);
    if (len + 1U > dest_size) {
        return SOCKIFY_ERR_OVERFLOW;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
    return SOCKIFY_OK;
}

static int parse_size(const char *text, size_t *out)
{
    char *end;
    unsigned long value;

    end = 0;
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0') {
        return SOCKIFY_ERR_INVALID;
    }
    *out = (size_t)value;
    return SOCKIFY_OK;
}

static int parse_uint(const char *text, unsigned int *out)
{
    char *end;
    unsigned long value;

    end = 0;
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0') {
        return SOCKIFY_ERR_INVALID;
    }
    *out = (unsigned int)value;
    return SOCKIFY_OK;
}

static int validate_tls(const struct sockify_proxy_config *config)
{
    int has_pem;
    int has_pfx;
    int has_store;
    int sources;

    if (config->target_tls_insecure && !config->target_tls_enabled) {
        return SOCKIFY_ERR_INVALID;
    }

    if (config->client_tls_enabled) {
        has_pem = config->client_tls_cert_file[0] != '\0' ||
                  config->client_tls_key_file[0] != '\0';
        has_pfx = config->client_tls_pfx_file[0] != '\0';
        has_store = config->client_tls_cert_store[0] != '\0' ||
                    config->client_tls_cert_thumbprint[0] != '\0';

        if (has_pem &&
            (config->client_tls_cert_file[0] == '\0' ||
             config->client_tls_key_file[0] == '\0')) {
            return SOCKIFY_ERR_INVALID;
        }

        sources = (has_pem ? 1 : 0) + (has_pfx ? 1 : 0) + (has_store ? 1 : 0);
        if (sources != 1) {
            return SOCKIFY_ERR_INVALID;
        }
    }

    return SOCKIFY_OK;
}

/*
 * Returns SOCKIFY_OK on a usable config, 1 when the program should
 * exit successfully without running (help/version), or
 * SOCKIFY_ERR_INVALID on a usage error.
 */
int sockify_cli_parse_args(int argc,
                           char **argv,
                           struct sockify_proxy_config *config,
                           FILE *output)
{
    int i;
    int positional;
    int rc;

    if (argv == 0 || config == 0) {
        return SOCKIFY_ERR_INVALID;
    }

    positional = 0;

    for (i = 1; i < argc; i++) {
        const char *arg;

        arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            sockify_cli_print_usage(output);
            return 1;
        }
        if (strcmp(arg, "--version") == 0) {
            if (output != 0) {
                fprintf(output, "sockify %s\n", SOCKIFY_VERSION);
            }
            return 1;
        }
        if (strcmp(arg, "--client-tls") == 0) {
            config->client_tls_enabled = 1;
            continue;
        }
        if (strcmp(arg, "--target-tls") == 0) {
            config->target_tls_enabled = 1;
            continue;
        }
        if (strcmp(arg, "--target-tls-insecure") == 0) {
            config->target_tls_insecure = 1;
            continue;
        }

        if (arg[0] == '-' && arg[1] == '-') {
            const char *value;

            /* All remaining options take a value. */
            if (i + 1 >= argc) {
                return SOCKIFY_ERR_INVALID;
            }
            value = argv[++i];

            if (strcmp(arg, "--max-connections") == 0) {
                if (parse_size(value, &config->max_connections) != SOCKIFY_OK) {
                    return SOCKIFY_ERR_INVALID;
                }
            } else if (strcmp(arg, "--buffer-size") == 0) {
                if (parse_size(value, &config->buffer_size) != SOCKIFY_OK) {
                    return SOCKIFY_ERR_INVALID;
                }
            } else if (strcmp(arg, "--handshake-timeout") == 0) {
                if (parse_uint(value, &config->handshake_timeout_ms) != SOCKIFY_OK) {
                    return SOCKIFY_ERR_INVALID;
                }
            } else if (strcmp(arg, "--idle-timeout") == 0) {
                if (parse_uint(value, &config->idle_timeout_ms) != SOCKIFY_OK) {
                    return SOCKIFY_ERR_INVALID;
                }
            } else if (strcmp(arg, "--connect-timeout") == 0) {
                if (parse_uint(value, &config->connect_timeout_ms) != SOCKIFY_OK) {
                    return SOCKIFY_ERR_INVALID;
                }
            } else if (strcmp(arg, "--log-level") == 0) {
                config->log_level = sockify_log_level_from_string(value);
            } else if (strcmp(arg, "--client-tls-cert") == 0) {
                rc = copy_str(config->client_tls_cert_file,
                              sizeof(config->client_tls_cert_file), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--client-tls-key") == 0) {
                rc = copy_str(config->client_tls_key_file,
                              sizeof(config->client_tls_key_file), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--client-tls-pfx") == 0) {
                rc = copy_str(config->client_tls_pfx_file,
                              sizeof(config->client_tls_pfx_file), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--client-tls-pfx-password") == 0) {
                rc = copy_str(config->client_tls_pfx_password,
                              sizeof(config->client_tls_pfx_password), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--client-tls-cert-store") == 0) {
                rc = copy_str(config->client_tls_cert_store,
                              sizeof(config->client_tls_cert_store), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--client-tls-cert-thumbprint") == 0) {
                rc = copy_str(config->client_tls_cert_thumbprint,
                              sizeof(config->client_tls_cert_thumbprint), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--target-tls-server-name") == 0) {
                rc = copy_str(config->target_tls_server_name,
                              sizeof(config->target_tls_server_name), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else if (strcmp(arg, "--target-tls-ca-file") == 0) {
                rc = copy_str(config->target_tls_ca_file,
                              sizeof(config->target_tls_ca_file), value);
                if (rc != SOCKIFY_OK) return SOCKIFY_ERR_INVALID;
            } else {
                return SOCKIFY_ERR_INVALID;
            }
            continue;
        }

        /* Positional: listen then target endpoint. */
        if (positional == 0) {
            if (sockify_net_parse_endpoint(arg, &config->listen_endpoint) != SOCKIFY_OK) {
                return SOCKIFY_ERR_INVALID;
            }
        } else if (positional == 1) {
            if (sockify_net_parse_endpoint(arg, &config->target_endpoint) != SOCKIFY_OK) {
                return SOCKIFY_ERR_INVALID;
            }
        } else {
            return SOCKIFY_ERR_INVALID;
        }
        positional++;
    }

    if (positional != 2) {
        return SOCKIFY_ERR_INVALID;
    }

    rc = validate_tls(config);
    if (rc != SOCKIFY_OK) {
        return rc;
    }

    return SOCKIFY_OK;
}
