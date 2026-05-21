#ifdef _WIN32

#include <stdlib.h>

#include "event_internal.h"

struct iocp_impl {
    HANDLE port;
};

static void iocp_destroy(struct sockify_event_loop *loop)
{
    struct iocp_impl *impl;

    impl = (struct iocp_impl *)loop->impl;
    if (impl != 0) {
        if (impl->port != 0) {
            CloseHandle(impl->port);
        }
        free(impl);
    }
    free(loop);
}

static int iocp_add(struct sockify_event_loop *loop,
                    sockify_socket_t fd,
                    int events,
                    sockify_event_callback callback,
                    void *user_data)
{
    struct iocp_impl *impl;
    HANDLE handle;

    SOCKIFY_UNUSED(events);
    SOCKIFY_UNUSED(callback);
    SOCKIFY_UNUSED(user_data);

    impl = (struct iocp_impl *)loop->impl;
    handle = CreateIoCompletionPort((HANDLE)fd, impl->port, (ULONG_PTR)fd, 0);
    if (handle == 0) {
        return SOCKIFY_ERR_SYS;
    }
    return SOCKIFY_OK;
}

static int iocp_modify(struct sockify_event_loop *loop,
                       sockify_socket_t fd,
                       int events)
{
    SOCKIFY_UNUSED(loop);
    SOCKIFY_UNUSED(fd);
    SOCKIFY_UNUSED(events);
    return SOCKIFY_OK;
}

static int iocp_remove(struct sockify_event_loop *loop,
                       sockify_socket_t fd)
{
    SOCKIFY_UNUSED(loop);
    SOCKIFY_UNUSED(fd);
    return SOCKIFY_OK;
}

static int iocp_run(struct sockify_event_loop *loop)
{
    struct iocp_impl *impl;
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;
    BOOL ok;

    impl = (struct iocp_impl *)loop->impl;
    loop->stopped = 0;
    while (!loop->stopped) {
        bytes = 0;
        key = 0;
        overlapped = 0;
        ok = GetQueuedCompletionStatus(impl->port, &bytes, &key, &overlapped, 1000);
        SOCKIFY_UNUSED(ok);
        SOCKIFY_UNUSED(bytes);
        SOCKIFY_UNUSED(key);
        SOCKIFY_UNUSED(overlapped);
        if (loop->tick_callback != 0) {
            loop->tick_callback(loop, loop->tick_user_data);
        }
    }
    return SOCKIFY_OK;
}

static void iocp_stop(struct sockify_event_loop *loop)
{
    loop->stopped = 1;
}

static const struct sockify_event_loop_ops iocp_ops = {
    iocp_destroy,
    iocp_add,
    iocp_modify,
    iocp_remove,
    iocp_run,
    iocp_stop
};

struct sockify_event_loop *sockify_ev_iocp_create(void)
{
    struct sockify_event_loop *loop;
    struct iocp_impl *impl;

    loop = (struct sockify_event_loop *)calloc(1U, sizeof(struct sockify_event_loop));
    if (loop == 0) return 0;
    impl = (struct iocp_impl *)calloc(1U, sizeof(struct iocp_impl));
    if (impl == 0) {
        free(loop);
        return 0;
    }
    impl->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
    if (impl->port == 0) {
        free(impl);
        free(loop);
        return 0;
    }
    loop->ops = &iocp_ops;
    loop->impl = impl;
    return loop;
}

#endif
