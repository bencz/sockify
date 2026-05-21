CC ?= cc
AR ?= ar
RM = rm -rf
MKDIR_P ?= mkdir -p
PKG_CONFIG ?= pkg-config

BUILD_DIR ?= build
TARGET ?= $(BUILD_DIR)/sockify
TEST_TARGET ?= $(BUILD_DIR)/test_sockify

CFLAGS_BASE ?= -std=c89 -pedantic -Iinclude
CFLAGS ?= $(CFLAGS_BASE) $(CFLAGS_EXTRA)
LDFLAGS ?=
LDLIBS ?=

UNAME_S := $(shell uname -s 2>/dev/null)
OPENSSL_AVAILABLE := $(shell $(PKG_CONFIG) --exists openssl >/dev/null 2>&1 && echo 1)
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null | sed 's/-I/-isystem /g')
OPENSSL_LDLIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)

CORE_SRCS := $(wildcard src/core/*.c)
WS_SRCS := $(wildcard src/ws/*.c)
PROXY_SRCS := $(wildcard src/proxy/*.c)
TRANSPORT_SRCS := $(wildcard src/transport/*.c)
TLS_SRCS := $(wildcard src/tls/tls_none.c)
EVENT_COMMON_SRCS := $(wildcard src/event/event_loop.c src/event/ev_poll.c)

ifeq ($(OS),Windows_NT)
	NET_SRCS := $(wildcard src/net/net_windows.c)
	EVENT_SRCS := $(wildcard src/event/event_loop.c src/event/ev_iocp.c)
	LDLIBS += -lws2_32
	EXE_EXT := .exe
else
	NET_SRCS := $(wildcard src/net/net_posix.c)
	EVENT_SRCS := $(EVENT_COMMON_SRCS)
	ifeq ($(OPENSSL_AVAILABLE),1)
		TLS_SRCS := $(wildcard src/tls/tls_openssl.c)
		CFLAGS += -DSOCKIFY_WITH_OPENSSL=1 $(OPENSSL_CFLAGS)
		LDLIBS += $(OPENSSL_LDLIBS)
	endif
	ifeq ($(UNAME_S),Linux)
		EVENT_SRCS += $(wildcard src/event/ev_epoll.c)
		CFLAGS += -D_GNU_SOURCE
	endif
	ifeq ($(UNAME_S),Darwin)
		EVENT_SRCS += $(wildcard src/event/ev_kqueue.c)
	endif
	EXE_EXT :=
endif

APP_SRCS := src/main.c $(CORE_SRCS) $(WS_SRCS) $(NET_SRCS) $(EVENT_SRCS) $(PROXY_SRCS) $(TRANSPORT_SRCS) $(TLS_SRCS)
TEST_SRCS := $(wildcard tests/*.c) $(CORE_SRCS) $(WS_SRCS) $(NET_SRCS) $(EVENT_SRCS) $(PROXY_SRCS) $(TRANSPORT_SRCS) $(TLS_SRCS)

APP_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(APP_SRCS))
TEST_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TEST_SRCS))
DEPS := $(APP_OBJS:.o=.d) $(TEST_OBJS:.o=.d)
DEPFLAGS ?= -MMD -MP

.PHONY: all clean test test-unit

all: $(TARGET)$(EXE_EXT)

$(TARGET)$(EXE_EXT): $(APP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(APP_OBJS) $(LDLIBS)

$(TEST_TARGET)$(EXE_EXT): $(TEST_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(TEST_OBJS) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

test: test-unit

test-unit: $(TEST_TARGET)$(EXE_EXT)
	$(TEST_TARGET)$(EXE_EXT)

clean:
	$(RM) $(BUILD_DIR)

-include $(DEPS)
