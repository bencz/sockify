#include "sockify/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static enum sockify_log_level g_log_level = SOCKIFY_LOG_INFO;

void sockify_log_set_level(enum sockify_log_level level)
{
    g_log_level = level;
}

enum sockify_log_level sockify_log_get_level(void)
{
    return g_log_level;
}

enum sockify_log_level sockify_log_level_from_string(const char *value)
{
    if (value != 0) {
        if (strcmp(value, "error") == 0) {
            return SOCKIFY_LOG_ERROR;
        }
        if (strcmp(value, "warn") == 0) {
            return SOCKIFY_LOG_WARN;
        }
        if (strcmp(value, "info") == 0) {
            return SOCKIFY_LOG_INFO;
        }
        if (strcmp(value, "debug") == 0) {
            return SOCKIFY_LOG_DEBUG;
        }
    }
    return SOCKIFY_LOG_INFO;
}

static const char *level_name(enum sockify_log_level level)
{
    switch (level) {
    case SOCKIFY_LOG_ERROR:
        return "error";
    case SOCKIFY_LOG_WARN:
        return "warn";
    case SOCKIFY_LOG_INFO:
        return "info";
    case SOCKIFY_LOG_DEBUG:
        return "debug";
    default:
        return "?";
    }
}

void sockify_log(enum sockify_log_level level, const char *fmt, ...)
{
    va_list args;

    if (level > g_log_level) {
        return;
    }

    fprintf(stderr, "sockify [%s] ", level_name(level));
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}
