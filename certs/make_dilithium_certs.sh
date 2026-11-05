#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
LIBOQS_PREFIX=${LIBOQS_PREFIX:-$HOME/pqc/install/liboqs-0.8.0}
WOLFSSL_PREFIX=${WOLFSSL_PREFIX:-$HOME/pqc/install/wolfssl-5.6.3-oqs}

gcc -O2 -o make_dilithium_certs make_dilithium_certs.c \
  -I"$WOLFSSL_PREFIX/include" -I"$LIBOQS_PREFIX/include" \
  -L"$WOLFSSL_PREFIX/lib" -L"$LIBOQS_PREFIX/lib" \
  -lwolfssl -loqs \
  -Wl,-rpath,"$WOLFSSL_PREFIX/lib" -Wl,-rpath,"$LIBOQS_PREFIX/lib"

for level in 2 3 5; do
  echo "== Dilithium$level =="
  ./make_dilithium_certs "$level"
done
