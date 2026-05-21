#include <stdio.h>

#include "sockify/cli.h"
#include "sockify/core.h"
#include "sockify/proxy.h"

int main(int argc, char **argv)
{
    struct sockify_proxy_config config;
    int rc;

    sockify_proxy_config_init(&config);
    rc = sockify_cli_parse_args(argc, argv, &config, stdout);
    if (rc == 1) {
        return 0;
    }
    if (rc != SOCKIFY_OK) {
        sockify_cli_print_usage(stderr);
        return 2;
    }

    rc = sockify_proxy_run(&config);
    if (rc != SOCKIFY_OK) {
        fprintf(stderr, "sockify: failed with error %d\n", rc);
        return 1;
    }

    return 0;
}
