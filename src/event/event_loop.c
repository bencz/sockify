#include <stdlib.h>

#include "event_internal.h"

struct sockify_event_loop *sockify_event_loop_create(void)
{
#ifdef _WIN32
    return sockify_ev_iocp_create();
#elif defined(__linux__)
    return sockify_ev_epoll_create();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return sockify_ev_kqueue_create();
#else
    return sockify_ev_poll_create();
#endif
}

void sockify_event_loop_destroy(struct sockify_event_loop *loop)
{
    if (loop == 0) {
        return;
    }
    loop->ops->destroy(loop);
}

int sockify_event_loop_add(struct sockify_event_loop *loop,
                           sockify_socket_t fd,
                           int events,
                           sockify_event_callback callback,
                           void *user_data)
{
    if (loop == 0 || callback == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    return loop->ops->add(loop, fd, events, callback, user_data);
}

int sockify_event_loop_modify(struct sockify_event_loop *loop,
                              sockify_socket_t fd,
                              int events)
{
    if (loop == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    return loop->ops->modify(loop, fd, events);
}

int sockify_event_loop_remove(struct sockify_event_loop *loop,
                              sockify_socket_t fd)
{
    if (loop == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    return loop->ops->remove(loop, fd);
}

int sockify_event_loop_run(struct sockify_event_loop *loop)
{
    if (loop == 0) {
        return SOCKIFY_ERR_INVALID;
    }
    return loop->ops->run(loop);
}

void sockify_event_loop_stop(struct sockify_event_loop *loop)
{
    if (loop == 0) {
        return;
    }
    loop->ops->stop(loop);
}

void sockify_event_loop_set_tick(struct sockify_event_loop *loop,
                                 sockify_event_tick_callback callback,
                                 void *user_data)
{
    if (loop == 0) {
        return;
    }
    loop->tick_callback = callback;
    loop->tick_user_data = user_data;
}
