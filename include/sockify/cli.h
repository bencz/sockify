#ifndef SOCKIFY_CLI_H
#define SOCKIFY_CLI_H

#include <stdio.h>

#include "sockify/proxy.h"

int sockify_cli_parse_args(int argc,
                           char **argv,
                           struct sockify_proxy_config *config,
                           FILE *output);

void sockify_cli_print_usage(FILE *out);

#endif
