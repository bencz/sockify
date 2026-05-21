#include <stdio.h>
#include <string.h>

#include "sockify/cli.h"
#include "sockify/proxy.h"

static int fail(const char *name)
{
    printf("test_cli: %s\n", name);
    return 1;
}

static int check_client_tls_pem(void)
{
    char *argv[] = {
        "sockify",
        "--client-tls",
        "--client-tls-cert",
        "server.pem",
        "--client-tls-key",
        "server.key",
        "127.0.0.1:6080",
        "127.0.0.1:5900"
    };
    struct sockify_proxy_config config;
    int rc;

    sockify_proxy_config_init(&config);
    rc = sockify_cli_parse_args(8, argv, &config, 0);
    if (rc != SOCKIFY_OK) return fail("client tls pem rc");
    if (!config.client_tls_enabled) return fail("client tls enabled");
    if (strcmp(config.client_tls_cert_file, "server.pem") != 0) return fail("client tls cert");
    if (strcmp(config.client_tls_key_file, "server.key") != 0) return fail("client tls key");
    if (strcmp(config.listen_endpoint.host, "127.0.0.1") != 0) return fail("listen host");
    if (strcmp(config.target_endpoint.port, "5900") != 0) return fail("target port");

    return 0;
}

static int check_target_tls_verify_name(void)
{
    char *argv[] = {
        "sockify",
        "--target-tls",
        "--target-tls-server-name",
        "target.example",
        "127.0.0.1:6080",
        "target.example:443"
    };
    struct sockify_proxy_config config;
    int rc;

    sockify_proxy_config_init(&config);
    rc = sockify_cli_parse_args(6, argv, &config, 0);
    if (rc != SOCKIFY_OK) return fail("target tls rc");
    if (!config.target_tls_enabled) return fail("target tls enabled");
    if (config.target_tls_insecure) return fail("target tls insecure default");
    if (strcmp(config.target_tls_server_name, "target.example") != 0) {
        return fail("target tls server name");
    }

    return 0;
}

static int check_target_tls_insecure_requires_tls(void)
{
    char *argv[] = {
        "sockify",
        "--target-tls-insecure",
        "127.0.0.1:6080",
        "target.example:443"
    };
    struct sockify_proxy_config config;
    int rc;

    sockify_proxy_config_init(&config);
    rc = sockify_cli_parse_args(4, argv, &config, 0);
    if (rc != SOCKIFY_ERR_INVALID) return fail("target insecure requires tls");

    return 0;
}

static int check_missing_client_key_rejected(void)
{
    char *argv[] = {
        "sockify",
        "--client-tls",
        "--client-tls-cert",
        "server.pem",
        "127.0.0.1:6080",
        "127.0.0.1:5900"
    };
    struct sockify_proxy_config config;
    int rc;

    sockify_proxy_config_init(&config);
    rc = sockify_cli_parse_args(6, argv, &config, 0);
    if (rc != SOCKIFY_ERR_INVALID) return fail("missing client key");

    return 0;
}

int test_cli(void)
{
    int failures;

    failures = 0;
    failures += check_client_tls_pem();
    failures += check_target_tls_verify_name();
    failures += check_target_tls_insecure_requires_tls();
    failures += check_missing_client_key_rejected();

    return failures;
}
