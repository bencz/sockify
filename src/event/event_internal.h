#ifndef SOCKIFY_EVENT_INTERNAL_H
#define SOCKIFY_EVENT_INTERNAL_H

#include "sockify/event_loop.h"

struct sockify_event_loop_ops {
    void (*destroy)(struct sockify_event_loop *loop);
    int (*add)(struct sockify_event_loop *loop,
               sockify_socket_t fd,
               int events,
               sockify_event_callback callback,
               void *user_data);
    int (*modify)(struct sockify_event_loop *loop,
                  sockify_socket_t fd,
                  int events);
    int (*remove)(struct sockify_event_loop *loop,
                  sockify_socket_t fd);
    int (*run)(struct sockify_event_loop *loop);
    void (*stop)(struct sockify_event_loop *loop);
};

struct sockify_event_loop {
    const struct sockify_event_loop_ops *ops;
    void *impl;
    int stopped;
    sockify_event_tick_callback tick_callback;
    void *tick_user_data;
};

struct sockify_event_loop *sockify_ev_poll_create(void);
struct sockify_event_loop *sockify_ev_epoll_create(void);
struct sockify_event_loop *sockify_ev_kqueue_create(void);
struct sockify_event_loop *sockify_ev_iocp_create(void);

#endif
