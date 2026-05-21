#ifndef SOCKIFY_EVENT_LOOP_H
#define SOCKIFY_EVENT_LOOP_H

#include "sockify/net.h"

#define SOCKIFY_EVENT_READ 0x01
#define SOCKIFY_EVENT_WRITE 0x02
#define SOCKIFY_EVENT_ERROR 0x04

struct sockify_event_loop;

typedef void (*sockify_event_callback)(struct sockify_event_loop *loop,
                                       sockify_socket_t fd,
                                       int events,
                                       void *user_data);

typedef void (*sockify_event_tick_callback)(struct sockify_event_loop *loop,
                                            void *user_data);

struct sockify_event_loop *sockify_event_loop_create(void);
void sockify_event_loop_destroy(struct sockify_event_loop *loop);
int sockify_event_loop_add(struct sockify_event_loop *loop,
                           sockify_socket_t fd,
                           int events,
                           sockify_event_callback callback,
                           void *user_data);
int sockify_event_loop_modify(struct sockify_event_loop *loop,
                              sockify_socket_t fd,
                              int events);
int sockify_event_loop_remove(struct sockify_event_loop *loop,
                              sockify_socket_t fd);
int sockify_event_loop_run(struct sockify_event_loop *loop);
void sockify_event_loop_stop(struct sockify_event_loop *loop);
void sockify_event_loop_set_tick(struct sockify_event_loop *loop,
                                 sockify_event_tick_callback callback,
                                 void *user_data);

#endif
