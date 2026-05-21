#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/time.h>

#include "event_internal.h"

struct kqueue_source {
    sockify_socket_t fd;
    int events;
    sockify_event_callback callback;
    void *user_data;
};

struct kqueue_impl {
    int kq;
    struct kqueue_source **sources;
    size_t count;
    size_t capacity;
};

static int kqueue_find(struct kqueue_impl *impl, sockify_socket_t fd)
{
    size_t i;

    for (i = 0; i < impl->count; i++) {
        if (impl->sources[i]->fd == fd) return (int)i;
    }
    return -1;
}

static int kqueue_grow(struct kqueue_impl *impl)
{
    struct kqueue_source **next_sources;
    size_t next_capacity;

    if (impl->count < impl->capacity) return SOCKIFY_OK;
    next_capacity = impl->capacity == 0U ? 64U : impl->capacity * 2U;
    next_sources = (struct kqueue_source **)realloc(impl->sources,
                                                    next_capacity * sizeof(struct kqueue_source *));
    if (next_sources == 0) return SOCKIFY_ERR_NOMEM;
    impl->sources = next_sources;
    impl->capacity = next_capacity;
    return SOCKIFY_OK;
}

static void set_kevent(struct kevent *ev,
                       struct kqueue_source *source,
                       short filter,
                       unsigned short flags)
{
    EV_SET(ev, (uintptr_t)source->fd, filter, flags, 0, 0, source);
}

static int update_filters(struct kqueue_impl *impl,
                          struct kqueue_source *source,
                          int old_events,
                          int new_events)
{
    struct kevent changes[2];
    int n;

    n = 0;
    if ((new_events & SOCKIFY_EVENT_READ) != 0 &&
        (old_events & SOCKIFY_EVENT_READ) == 0) {
        set_kevent(&changes[n++], source, EVFILT_READ, EV_ADD | EV_ENABLE);
    } else if ((new_events & SOCKIFY_EVENT_READ) == 0 &&
               (old_events & SOCKIFY_EVENT_READ) != 0) {
        set_kevent(&changes[n++], source, EVFILT_READ, EV_DELETE);
    }

    if ((new_events & SOCKIFY_EVENT_WRITE) != 0 &&
        (old_events & SOCKIFY_EVENT_WRITE) == 0) {
        set_kevent(&changes[n++], source, EVFILT_WRITE, EV_ADD | EV_ENABLE);
    } else if ((new_events & SOCKIFY_EVENT_WRITE) == 0 &&
               (old_events & SOCKIFY_EVENT_WRITE) != 0) {
        set_kevent(&changes[n++], source, EVFILT_WRITE, EV_DELETE);
    }

    if (n == 0) {
        return SOCKIFY_OK;
    }
    if (kevent(impl->kq, changes, n, 0, 0, 0) < 0) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

static void kqueue_destroy(struct sockify_event_loop *loop)
{
    struct kqueue_impl *impl;
    size_t i;

    impl = (struct kqueue_impl *)loop->impl;
    if (impl != 0) {
        for (i = 0; i < impl->count; i++) free(impl->sources[i]);
        free(impl->sources);
        if (impl->kq >= 0) close(impl->kq);
        free(impl);
    }
    free(loop);
}

static int kqueue_add_common(struct sockify_event_loop *loop,
                             sockify_socket_t fd,
                             int events,
                             sockify_event_callback callback,
                             void *user_data)
{
    struct kqueue_impl *impl;
    struct kqueue_source *source;
    int rc;

    impl = (struct kqueue_impl *)loop->impl;
    if (kqueue_find(impl, fd) >= 0) return SOCKIFY_ERR_INVALID;
    rc = kqueue_grow(impl);
    if (rc != SOCKIFY_OK) return rc;
    source = (struct kqueue_source *)calloc(1U, sizeof(struct kqueue_source));
    if (source == 0) return SOCKIFY_ERR_NOMEM;
    source->fd = fd;
    source->events = events;
    source->callback = callback;
    source->user_data = user_data;
    rc = update_filters(impl, source, 0, events);
    if (rc != SOCKIFY_OK) {
        free(source);
        return rc;
    }

    impl->sources[impl->count++] = source;
    return SOCKIFY_OK;
}

static int kqueue_modify_common(struct sockify_event_loop *loop,
                                sockify_socket_t fd,
                                int events)
{
    struct kqueue_impl *impl;
    struct kqueue_source *source;
    int index;
    int rc;

    impl = (struct kqueue_impl *)loop->impl;
    index = kqueue_find(impl, fd);
    if (index < 0) return SOCKIFY_ERR_INVALID;
    source = impl->sources[index];
    rc = update_filters(impl, source, source->events, events);
    if (rc != SOCKIFY_OK) return rc;
    source->events = events;
    return SOCKIFY_OK;
}

static int kqueue_remove_common(struct sockify_event_loop *loop,
                                sockify_socket_t fd)
{
    struct kqueue_impl *impl;
    struct kqueue_source *source;
    struct kevent changes[2];
    int index;
    size_t pos;

    impl = (struct kqueue_impl *)loop->impl;
    index = kqueue_find(impl, fd);
    if (index < 0) return SOCKIFY_ERR_INVALID;
    pos = (size_t)index;
    source = impl->sources[pos];
    if ((source->events & SOCKIFY_EVENT_READ) != 0) {
        set_kevent(&changes[0], source, EVFILT_READ, EV_DELETE);
        kevent(impl->kq, changes, 1, 0, 0, 0);
    }
    if ((source->events & SOCKIFY_EVENT_WRITE) != 0) {
        set_kevent(&changes[0], source, EVFILT_WRITE, EV_DELETE);
        kevent(impl->kq, changes, 1, 0, 0, 0);
    }
    free(source);
    if (pos + 1U < impl->count) impl->sources[pos] = impl->sources[impl->count - 1U];
    impl->count--;
    return SOCKIFY_OK;
}

static int kqueue_run_common(struct sockify_event_loop *loop)
{
    struct kqueue_impl *impl;
    struct kevent events[128];
    struct kqueue_source *source;
    struct timespec timeout;
    int n;
    int i;
    int event_mask;

    impl = (struct kqueue_impl *)loop->impl;
    loop->stopped = 0;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    while (!loop->stopped) {
        n = kevent(impl->kq, 0, 0, events, 128, &timeout);
        if (n < 0) return SOCKIFY_ERR_SYS;
        for (i = 0; i < n; i++) {
            source = (struct kqueue_source *)events[i].udata;
            if (source == 0) continue;
            event_mask = 0;
            if (events[i].filter == EVFILT_READ) event_mask |= SOCKIFY_EVENT_READ;
            if (events[i].filter == EVFILT_WRITE) event_mask |= SOCKIFY_EVENT_WRITE;
            if ((events[i].flags & EV_ERROR) != 0) event_mask |= SOCKIFY_EVENT_ERROR;
            source->callback(loop, source->fd, event_mask, source->user_data);
            if (loop->stopped) break;
        }
        if (loop->tick_callback != 0) {
            loop->tick_callback(loop, loop->tick_user_data);
        }
    }
    return SOCKIFY_OK;
}

static void kqueue_stop_common(struct sockify_event_loop *loop)
{
    loop->stopped = 1;
}

static const struct sockify_event_loop_ops kqueue_ops = {
    kqueue_destroy,
    kqueue_add_common,
    kqueue_modify_common,
    kqueue_remove_common,
    kqueue_run_common,
    kqueue_stop_common
};

struct sockify_event_loop *sockify_ev_kqueue_create(void)
{
    struct sockify_event_loop *loop;
    struct kqueue_impl *impl;

    loop = (struct sockify_event_loop *)calloc(1U, sizeof(struct sockify_event_loop));
    if (loop == 0) return 0;
    impl = (struct kqueue_impl *)calloc(1U, sizeof(struct kqueue_impl));
    if (impl == 0) {
        free(loop);
        return 0;
    }
    impl->kq = kqueue();
    if (impl->kq < 0) {
        free(impl);
        free(loop);
        return 0;
    }
    loop->ops = &kqueue_ops;
    loop->impl = impl;
    return loop;
}

#endif
