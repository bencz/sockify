#ifndef SOCKIFY_LOG_H
#define SOCKIFY_LOG_H

#include "sockify/core.h"

enum sockify_log_level {
    SOCKIFY_LOG_ERROR = 0,
    SOCKIFY_LOG_WARN = 1,
    SOCKIFY_LOG_INFO = 2,
    SOCKIFY_LOG_DEBUG = 3
};

void sockify_log_set_level(enum sockify_log_level level);
enum sockify_log_level sockify_log_get_level(void);
enum sockify_log_level sockify_log_level_from_string(const char *value);
void sockify_log(enum sockify_log_level level, const char *fmt, ...);

#endif
