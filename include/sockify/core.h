#ifndef SOCKIFY_CORE_H
#define SOCKIFY_CORE_H

#include <stddef.h>
#include <limits.h>

#define SOCKIFY_VERSION "0.1.0"

#define SOCKIFY_OK 0
#define SOCKIFY_ERR_INVALID -1
#define SOCKIFY_ERR_NOMEM -2
#define SOCKIFY_ERR_OVERFLOW -3
#define SOCKIFY_ERR_AGAIN -4
#define SOCKIFY_ERR_CLOSED -5
#define SOCKIFY_ERR_SYS -6
#define SOCKIFY_ERR_PROTOCOL -7
#define SOCKIFY_ERR_UNSUPPORTED -8

typedef unsigned char sockify_u8;

#if USHRT_MAX == 65535U
typedef unsigned short sockify_u16;
#else
#error "sockify requires a 16-bit unsigned short"
#endif

#if UINT_MAX == 4294967295U
typedef unsigned int sockify_u32;
#elif ULONG_MAX == 4294967295UL
typedef unsigned long sockify_u32;
#else
#error "sockify requires a 32-bit unsigned integer type"
#endif

#if ULONG_MAX > 4294967295UL
typedef unsigned long sockify_u64;
#elif defined(_MSC_VER)
typedef unsigned __int64 sockify_u64;
#else
typedef unsigned long long sockify_u64;
#endif

#define SOCKIFY_UNUSED(x) ((void)(x))

#endif
