#include <stdio.h>

#include "sockify/net.h"
#include "sockify/transport.h"

static int fail(const char *name)
{
    printf("test_transport: %s\n", name);
    return 1;
}

static int check_plain_init(void)
{
    struct sockify_transport transport;

    if (sockify_transport_init_plain(&transport, sockify_net_invalid_socket()) != SOCKIFY_OK) {
        return fail("plain init");
    }
    if (sockify_transport_fd(&transport) != sockify_net_invalid_socket()) {
        return fail("plain fd");
    }
    if (sockify_transport_wants_read(&transport)) {
        return fail("plain wants read");
    }
    if (sockify_transport_wants_write(&transport)) {
        return fail("plain wants write");
    }
    sockify_transport_destroy(&transport);

    return 0;
}

int test_transport(void)
{
    int failures;

    failures = 0;
    failures += check_plain_init();

    return failures;
}
