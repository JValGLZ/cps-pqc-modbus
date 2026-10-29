#!/usr/bin/env bash
# Build stock wolfSSL 5.6.3 (no liboqs) for C1: Modbus over classical TLS 1.3 (ECDHE + ECDSA P-256).
# Same version Shahid et al. used, so C1 and C2 differ only in the PQC algorithms.
# Jose's liboqs build (C2/C3) goes in stack/build_pqc.sh and installs to a different prefix.
#
#   stack/build_wolfssl_classic.sh            # installs to ~/pqc/install/wolfssl-5.6.3
#   PREFIX=/opt/wolfssl stack/build_wolfssl_classic.sh
#
# Needs: git build-essential autoconf automake libtool  (sudo apt install -y git build-essential autoconf automake libtool)
set -euo pipefail
VER=5.6.3
SRC=${SRC:-$HOME/pqc/src}
PREFIX=${PREFIX:-$HOME/pqc/install/wolfssl-$VER}
mkdir -p "$SRC"
# wolfSSL 5.6.3's configure needs `colrm` (Ubuntu: bsdextrautils). If it's missing, provide a tiny stand-in.
if ! colrm </dev/null >/dev/null 2>&1; then
  mkdir -p "$SRC/.shim"
  printf '#!/bin/sh\n[ -z "$1" ] && exec cat\nexec cut -c1-$(( $1 - 1 ))\n' > "$SRC/.shim/colrm"
  chmod +x "$SRC/.shim/colrm"
  export PATH="$SRC/.shim:$PATH"
  echo "note: using a colrm stand-in (install bsdextrautils to avoid this)"
fi
cd "$SRC"
[ -d wolfssl-$VER ] || git clone --depth 1 --branch v$VER-stable https://github.com/wolfSSL/wolfssl.git wolfssl-$VER
cd wolfssl-$VER
./autogen.sh >/dev/null
# TLS 1.3 + ECC (P-256/384/521) + X25519 + AES-GCM-SHA384 + session tickets (for the resumption experiment later).
./configure --prefix="$PREFIX" \
  --enable-tls13 --enable-ecc --enable-curve25519 --enable-aesgcm --enable-sha384 --enable-sha512 \
  --enable-supportedcurves --enable-session-ticket --enable-certgen --enable-certext \
  --disable-oldtls --disable-examples --disable-crypttests \
  CFLAGS="-O2" >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "wolfSSL $VER installed to $PREFIX"
grep LIBWOLFSSL_VERSION_STRING "$PREFIX/include/wolfssl/version.h"
