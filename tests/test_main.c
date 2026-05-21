#include <stdio.h>

#include "sockify/log.h"
#include "sockify/net.h"
#include "sockify/event_loop.h"
#include "sockify/proxy.h"

int test_byte_order(void);
int test_base64(void);
int test_sha1(void);
int test_ws(void);
int test_buffer(void);
int test_cli(void);
int test_transport(void);
int test_tls(void);

static int test_platform_headers(void)
{
    struct sockify_event_loop *loop;
    struct sockify_proxy_config config;

    if (sockify_log_level_from_string("debug") != SOCKIFY_LOG_DEBUG) {
        return 1;
    }
    if (sockify_net_invalid_socket() == (sockify_socket_t)0) {
        return 0;
    }
    loop = sockify_event_loop_create();
    if (loop == 0) {
        return 1;
    }
    sockify_event_loop_destroy(loop);
    sockify_proxy_config_init(&config);
    if (config.max_connections == 0U) {
        return 1;
    }
    if (config.buffer_size == 0U) {
        return 1;
    }
    if (config.accept_budget == 0U) {
        return 1;
    }
    if (config.read_budget == 0U) {
        return 1;
    }
    if (config.write_budget == 0U) {
        return 1;
    }
    return 0;
}

int main(void)
{
    int failures;

    failures = 0;
    failures += test_byte_order();
    failures += test_base64();
    failures += test_sha1();
    failures += test_ws();
    failures += test_buffer();
    failures += test_cli();
    failures += test_transport();
    failures += test_tls();
    failures += test_platform_headers();

    if (failures != 0) {
        printf("FAIL %d\n", failures);
        return 1;
    }

    printf("PASS\n");
    return 0;
}
