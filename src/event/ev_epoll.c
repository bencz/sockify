#ifdef __linux__

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "event_internal.h"

struct epoll_source {
    sockify_socket_t fd;
    int events;
    sockify_event_callback callback;
    void *user_data;
};

struct epoll_impl {
    int epfd;
    struct epoll_source **sources;
    size_t count;
    size_t capacity;
};

static unsigned int to_epoll_events(int events)
{
    unsigned int out;

    out = 0U;
    if ((events & SOCKIFY_EVENT_READ) != 0) out |= EPOLLIN;
    if ((events & SOCKIFY_EVENT_WRITE) != 0) out |= EPOLLOUT;
    return out;
}

static int from_epoll_events(unsigned int events)
{
    int out;

    out = 0;
    if ((events & (EPOLLIN | EPOLLHUP)) != 0U) out |= SOCKIFY_EVENT_READ;
    if ((events & EPOLLOUT) != 0U) out |= SOCKIFY_EVENT_WRITE;
    if ((events & EPOLLERR) != 0U) out |= SOCKIFY_EVENT_ERROR;
    return out;
}

static int epoll_find(struct epoll_impl *impl, sockify_socket_t fd)
{
    size_t i;

    for (i = 0; i < impl->count; i++) {
        if (impl->sources[i]->fd == fd) return (int)i;
    }
    return -1;
}

static int epoll_grow(struct epoll_impl *impl)
{
    struct epoll_source **next_sources;
    size_t next_capacity;

    if (impl->count < impl->capacity) return SOCKIFY_OK;
    next_capacity = impl->capacity == 0U ? 64U : impl->capacity * 2U;
    next_sources = (struct epoll_source **)realloc(impl->sources,
                                                   next_capacity * sizeof(struct epoll_source *));
    if (next_sources == 0) return SOCKIFY_ERR_NOMEM;
    impl->sources = next_sources;
    impl->capacity = next_capacity;
    return SOCKIFY_OK;
}

static void epoll_destroy(struct sockify_event_loop *loop)
{
    struct epoll_impl *impl;
    size_t i;

    impl = (struct epoll_impl *)loop->impl;
    if (impl != 0) {
        for (i = 0; i < impl->count; i++) free(impl->sources[i]);
        free(impl->sources);
        if (impl->epfd >= 0) close(impl->epfd);
        free(impl);
    }
    free(loop);
}

static int epoll_add_common(struct sockify_event_loop *loop,
                            sockify_socket_t fd,
                            int events,
                            sockify_event_callback callback,
                            void *user_data)
{
    struct epoll_impl *impl;
    struct epoll_source *source;
    struct epoll_event ev;
    int rc;

    impl = (struct epoll_impl *)loop->impl;
    if (epoll_find(impl, fd) >= 0) return SOCKIFY_ERR_INVALID;
    rc = epoll_grow(impl);
    if (rc != SOCKIFY_OK) return rc;

    source = (struct epoll_source *)calloc(1U, sizeof(struct epoll_source));
    if (source == 0) return SOCKIFY_ERR_NOMEM;
    source->fd = fd;
    source->events = events;
    source->callback = callback;
    source->user_data = user_data;

    memset(&ev, 0, sizeof(ev));
    ev.events = to_epoll_events(events);
    ev.data.ptr = source;
    if (epoll_ctl(impl->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        free(source);
        return SOCKIFY_ERR_SYS;
    }

    impl->sources[impl->count++] = source;
    return SOCKIFY_OK;
}

static int epoll_modify_common(struct sockify_event_loop *loop,
                               sockify_socket_t fd,
                               int events)
{
    struct epoll_impl *impl;
    struct epoll_source *source;
    struct epoll_event ev;
    int index;

    impl = (struct epoll_impl *)loop->impl;
    index = epoll_find(impl, fd);
    if (index < 0) return SOCKIFY_ERR_INVALID;
    source = impl->sources[index];
    source->events = events;

    memset(&ev, 0, sizeof(ev));
    ev.events = to_epoll_events(events);
    ev.data.ptr = source;
    if (epoll_ctl(impl->epfd, EPOLL_CTL_MOD, fd, &ev) != 0) return SOCKIFY_ERR_SYS;
    return SOCKIFY_OK;
}

static int epoll_remove_common(struct sockify_event_loop *loop,
                               sockify_socket_t fd)
{
    struct epoll_impl *impl;
    int index;
    size_t pos;

    impl = (struct epoll_impl *)loop->impl;
    index = epoll_find(impl, fd);
    if (index < 0) return SOCKIFY_ERR_INVALID;
    epoll_ctl(impl->epfd, EPOLL_CTL_DEL, fd, 0);
    pos = (size_t)index;
    free(impl->sources[pos]);
    if (pos + 1U < impl->count) impl->sources[pos] = impl->sources[impl->count - 1U];
    impl->count--;
    return SOCKIFY_OK;
}

static int epoll_run_common(struct sockify_event_loop *loop)
{
    struct epoll_impl *impl;
    struct epoll_event events[128];
    struct epoll_source *source;
    int n;
    int i;

    impl = (struct epoll_impl *)loop->impl;
    loop->stopped = 0;
    while (!loop->stopped) {
        n = epoll_wait(impl->epfd, events, 128, 1000);
        if (n < 0) return SOCKIFY_ERR_SYS;
        for (i = 0; i < n; i++) {
            source = (struct epoll_source *)events[i].data.ptr;
            source->callback(loop, source->fd, from_epoll_events(events[i].events), source->user_data);
            if (loop->stopped) break;
        }
        if (loop->tick_callback != 0) {
            loop->tick_callback(loop, loop->tick_user_data);
        }
    }
    return SOCKIFY_OK;
}

static void epoll_stop_common(struct sockify_event_loop *loop)
{
    loop->stopped = 1;
}

static const struct sockify_event_loop_ops epoll_ops = {
    epoll_destroy,
    epoll_add_common,
    epoll_modify_common,
    epoll_remove_common,
    epoll_run_common,
    epoll_stop_common
};

struct sockify_event_loop *sockify_ev_epoll_create(void)
{
    struct sockify_event_loop *loop;
    struct epoll_impl *impl;

    loop = (struct sockify_event_loop *)calloc(1U, sizeof(struct sockify_event_loop));
    if (loop == 0) return 0;
    impl = (struct epoll_impl *)calloc(1U, sizeof(struct epoll_impl));
    if (impl == 0) {
        free(loop);
        return 0;
    }
    impl->epfd = epoll_create1(0);
    if (impl->epfd < 0) {
        free(impl);
        free(loop);
        return 0;
    }
    loop->ops = &epoll_ops;
    loop->impl = impl;
    return loop;
}

#endif
