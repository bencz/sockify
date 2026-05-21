#ifndef _WIN32

#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include "event_internal.h"

struct poll_source {
    sockify_socket_t fd;
    int events;
    sockify_event_callback callback;
    void *user_data;
};

struct poll_impl {
    struct poll_source *sources;
    struct pollfd *pfds;
    size_t count;
    size_t capacity;
};

static short to_poll_events(int events)
{
    short out;

    out = 0;
    if ((events & SOCKIFY_EVENT_READ) != 0) out = (short)(out | POLLIN);
    if ((events & SOCKIFY_EVENT_WRITE) != 0) out = (short)(out | POLLOUT);
    return out;
}

static int from_poll_events(short events)
{
    int out;

    out = 0;
    if ((events & (POLLIN | POLLHUP)) != 0) out |= SOCKIFY_EVENT_READ;
    if ((events & POLLOUT) != 0) out |= SOCKIFY_EVENT_WRITE;
    if ((events & (POLLERR | POLLNVAL)) != 0) out |= SOCKIFY_EVENT_ERROR;
    return out;
}

static int poll_find(struct poll_impl *impl, sockify_socket_t fd)
{
    size_t i;

    for (i = 0; i < impl->count; i++) {
        if (impl->sources[i].fd == fd) {
            return (int)i;
        }
    }
    return -1;
}

static int poll_grow(struct poll_impl *impl)
{
    struct poll_source *next_sources;
    struct pollfd *next_pfds;
    size_t next_capacity;

    if (impl->count < impl->capacity) {
        return SOCKIFY_OK;
    }

    next_capacity = impl->capacity == 0U ? 64U : impl->capacity * 2U;
    next_sources = (struct poll_source *)realloc(impl->sources,
                                                 next_capacity * sizeof(struct poll_source));
    if (next_sources == 0) {
        return SOCKIFY_ERR_NOMEM;
    }

    next_pfds = (struct pollfd *)realloc(impl->pfds,
                                         next_capacity * sizeof(struct pollfd));
    if (next_pfds == 0) {
        impl->sources = next_sources;
        return SOCKIFY_ERR_NOMEM;
    }
    impl->sources = next_sources;
    impl->pfds = next_pfds;
    impl->capacity = next_capacity;
    return SOCKIFY_OK;
}

static void poll_destroy(struct sockify_event_loop *loop)
{
    struct poll_impl *impl;

    impl = (struct poll_impl *)loop->impl;
    if (impl != 0) {
        free(impl->sources);
        free(impl->pfds);
        free(impl);
    }
    free(loop);
}

static int poll_add(struct sockify_event_loop *loop,
                    sockify_socket_t fd,
                    int events,
                    sockify_event_callback callback,
                    void *user_data)
{
    struct poll_impl *impl;
    int rc;

    impl = (struct poll_impl *)loop->impl;
    if (poll_find(impl, fd) >= 0) {
        return SOCKIFY_ERR_INVALID;
    }
    rc = poll_grow(impl);
    if (rc != SOCKIFY_OK) {
        return rc;
    }

    impl->sources[impl->count].fd = fd;
    impl->sources[impl->count].events = events;
    impl->sources[impl->count].callback = callback;
    impl->sources[impl->count].user_data = user_data;
    impl->count++;
    return SOCKIFY_OK;
}

static int poll_modify(struct sockify_event_loop *loop,
                       sockify_socket_t fd,
                       int events)
{
    struct poll_impl *impl;
    int index;

    impl = (struct poll_impl *)loop->impl;
    index = poll_find(impl, fd);
    if (index < 0) {
        return SOCKIFY_ERR_INVALID;
    }
    impl->sources[index].events = events;
    return SOCKIFY_OK;
}

static int poll_remove(struct sockify_event_loop *loop,
                       sockify_socket_t fd)
{
    struct poll_impl *impl;
    int index;
    size_t pos;

    impl = (struct poll_impl *)loop->impl;
    index = poll_find(impl, fd);
    if (index < 0) {
        return SOCKIFY_ERR_INVALID;
    }

    pos = (size_t)index;
    if (pos + 1U < impl->count) {
        impl->sources[pos] = impl->sources[impl->count - 1U];
    }
    impl->count--;
    return SOCKIFY_OK;
}

static int poll_run(struct sockify_event_loop *loop)
{
    struct poll_impl *impl;
    size_t i;
    int rc;
    int events;

    impl = (struct poll_impl *)loop->impl;
    loop->stopped = 0;

    while (!loop->stopped) {
        if (impl->count == 0U) {
            return SOCKIFY_OK;
        }

        for (i = 0; i < impl->count; i++) {
            impl->pfds[i].fd = impl->sources[i].fd;
            impl->pfds[i].events = to_poll_events(impl->sources[i].events);
            impl->pfds[i].revents = 0;
        }

        rc = poll(impl->pfds, (nfds_t)impl->count, 1000);
        if (rc < 0) {
            return SOCKIFY_ERR_SYS;
        }

        if (rc > 0) {
            for (i = 0; i < impl->count; i++) {
                if (impl->pfds[i].revents != 0) {
                    events = from_poll_events(impl->pfds[i].revents);
                    impl->sources[i].callback(loop,
                                              impl->sources[i].fd,
                                              events,
                                              impl->sources[i].user_data);
                    if (loop->stopped) {
                        break;
                    }
                }
            }
        }
        if (loop->tick_callback != 0) {
            loop->tick_callback(loop, loop->tick_user_data);
        }
    }

    return SOCKIFY_OK;
}

static void poll_stop(struct sockify_event_loop *loop)
{
    loop->stopped = 1;
}

static const struct sockify_event_loop_ops poll_ops = {
    poll_destroy,
    poll_add,
    poll_modify,
    poll_remove,
    poll_run,
    poll_stop
};

struct sockify_event_loop *sockify_ev_poll_create(void)
{
    struct sockify_event_loop *loop;
    struct poll_impl *impl;

    loop = (struct sockify_event_loop *)calloc(1U, sizeof(struct sockify_event_loop));
    if (loop == 0) {
        return 0;
    }
    impl = (struct poll_impl *)calloc(1U, sizeof(struct poll_impl));
    if (impl == 0) {
        free(loop);
        return 0;
    }

    loop->ops = &poll_ops;
    loop->impl = impl;
    return loop;
}

#endif
