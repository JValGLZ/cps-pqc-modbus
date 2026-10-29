# Build:   make                 -> C0 only (plain TCP), no dependencies
#          make TLS=1 WOLFSSL_PREFIX=$HOME/pqc/install/wolfssl-5.6.3   -> C0-C3 (C2/C3 need a --with-liboqs wolfSSL)
CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=c11

LDLIBS  += -lm

ifeq ($(TLS),1)
  WOLFSSL_PREFIX ?= $(HOME)/pqc/install/wolfssl-5.6.3
  CFLAGS  += -DUSE_WOLFSSL -I$(WOLFSSL_PREFIX)/include
  LDFLAGS += -L$(WOLFSSL_PREFIX)/lib -Wl,-rpath,$(WOLFSSL_PREFIX)/lib
  LDLIBS  += -lwolfssl
endif

COMMON := transport/transport.c modbus/modbus.c
HDRS   := transport/transport.h modbus/modbus.h

all: bin/mb_server bin/mb_poll

bin:
	mkdir -p bin

bin/mb_server: modbus/mb_server.c $(COMMON) $(HDRS) | bin
	$(CC) $(CFLAGS) -o $@ modbus/mb_server.c $(COMMON) $(LDFLAGS) $(LDLIBS)

bin/mb_poll: harness/mb_poll.c $(COMMON) $(HDRS) | bin
	$(CC) $(CFLAGS) -o $@ harness/mb_poll.c $(COMMON) $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf bin

.PHONY: all clean
