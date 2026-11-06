# Build:   make                 -> C0 only (plain TCP), no dependencies
#          make TLS=1 WOLFSSL_PREFIX=$HOME/pqc/install/wolfssl-5.6.3   -> C0-C1 (stock wolfSSL)
#          make TLS=1 WOLFSSL_PREFIX=$HOME/pqc/install/wolfssl-5.6.3-oqs \
#                     OQS_PREFIX=$HOME/pqc/install/liboqs-0.8.0        -> C0-C3 (wolfSSL built --with-liboqs)
# Don't pass LDFLAGS/LDLIBS on the command line: GNU Make then ignores the += lines below.
CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=c11

# -pthread: mb_server's sensor thread. glibc >= 2.34 (Debian 12, Ubuntu 22.04+) has pthreads in
# libc so it links either way; glibc 2.31 (Debian 11, JOSPC-wsl2) needs it explicitly.
CFLAGS  += -pthread
LDLIBS  += -lm -pthread

ifeq ($(TLS),1)
  WOLFSSL_PREFIX ?= $(HOME)/pqc/install/wolfssl-5.6.3
  CFLAGS  += -DUSE_WOLFSSL -I$(WOLFSSL_PREFIX)/include
  LDFLAGS += -L$(WOLFSSL_PREFIX)/lib -Wl,-rpath,$(WOLFSSL_PREFIX)/lib
  LDLIBS  += -lwolfssl
  ifneq ($(OQS_PREFIX),)
    # libwolfssl needs liboqs. --disable-new-dtags writes DT_RPATH instead of DT_RUNPATH:
    # RUNPATH only covers the binary's direct libraries, so liboqs (needed by libwolfssl,
    # not by us) would not be found at run time without LD_LIBRARY_PATH.
    LDFLAGS += -L$(OQS_PREFIX)/lib -Wl,-rpath,$(OQS_PREFIX)/lib -Wl,--disable-new-dtags
    LDLIBS  += -loqs
  endif
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
