#!/usr/bin/env bash
# Build liboqs 0.8.0 + wolfSSL 5.6.3 --with-liboqs for C2/C3: Modbus over post-quantum TLS 1.3.
# Jhonny's stock-wolfSSL build (C1) is stack/build_wolfssl_classic.sh; this is the PQC counterpart,
# installing to its own prefix so C1 and C2/C3 binaries never collide.
#
#   stack/build_pqc.sh                         # installs to ~/pqc/install/wolfssl-5.6.3-oqs
#   PREFIX=/opt/wolfssl-oqs stack/build_pqc.sh
#
# Needs: git build-essential cmake ninja-build autoconf automake libtool libssl-dev
set -euo pipefail
LIBOQS_VER=0.8.0
WOLFSSL_VER=5.6.3
SRC=${SRC:-$HOME/pqc/src}
LIBOQS_PREFIX=${LIBOQS_PREFIX:-$HOME/pqc/install/liboqs-$LIBOQS_VER}
WOLFSSL_PREFIX=${PREFIX:-$HOME/pqc/install/wolfssl-$WOLFSSL_VER-oqs}
mkdir -p "$SRC"

# wolfSSL's ./configure needs `colrm` (Ubuntu/Debian: bsdextrautils) to generate its options header.
# Shimmed unconditionally rather than relying on apt, since that package isn't always reachable
# (hit a stale Debian security-mirror 404 on this exact package while building this script).
mkdir -p "$SRC/.shim"
printf '#!/bin/sh\n[ -z "$1" ] && exec cat\nexec cut -c1-$(( $1 - 1 ))\n' > "$SRC/.shim/colrm"
chmod +x "$SRC/.shim/colrm"
export PATH="$SRC/.shim:$PATH"

cd "$SRC"

### 1. liboqs ###
[ -d liboqs ] || git clone --branch $LIBOQS_VER https://github.com/open-quantum-safe/liboqs.git
cd liboqs
rm -rf build   # avoid a stale CMake cache from a previous failed configure
mkdir -p build && cd build
# Explicit OpenSSL hints: this environment's CMake doesn't reliably auto-detect the Debian
# multiarch path (/usr/lib/x86_64-linux-gnu) for libcrypto, even with libssl-dev installed.
cmake -GNinja -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX="$LIBOQS_PREFIX" \
  -DOPENSSL_ROOT_DIR=/usr \
  -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so \
  -DOPENSSL_SSL_LIBRARY=/usr/lib/x86_64-linux-gnu/libssl.so \
  -DOPENSSL_INCLUDE_DIR=/usr/include \
  ..
ninja
ninja install
echo "== liboqs $LIBOQS_VER installed to $LIBOQS_PREFIX =="
echo "-- smoke test (Kyber768 / Dilithium3) --"
./tests/speed_kem -d 1 kyber768
./tests/speed_sig -d 1 dilithium3

### 2. wolfSSL, built against liboqs ###
cd "$SRC"
[ -d wolfssl-$WOLFSSL_VER-oqs ] || git clone --branch v$WOLFSSL_VER-stable https://github.com/wolfSSL/wolfssl.git wolfssl-$WOLFSSL_VER-oqs
cd wolfssl-$WOLFSSL_VER-oqs
./autogen.sh >/dev/null

# Known wolfSSL-5.6.3 / liboqs-0.8.0 mismatch: wolfSSL's SPHINCS+ glue code uses the older
# "sphincs_shake256_*" liboqs symbol names; 0.8.0 renamed them to "sphincs_shake_*" (dropped the
# redundant "256"). We don't use SPHINCS+ (only Kyber/Dilithium), so patch the two affected files
# rather than fight it. Safe to rerun (no-op if already patched).
sed -i 's/_sphincs_shake256_/_sphincs_shake_/g' wolfssl/wolfcrypt/sphincs.h wolfcrypt/src/sphincs.c

./configure --prefix="$WOLFSSL_PREFIX" \
  --enable-tls13 --enable-ecc --enable-curve25519 --enable-aesgcm --enable-sha384 --enable-sha512 \
  --enable-supportedcurves --enable-session-ticket --enable-certgen --enable-certext \
  --disable-oldtls --disable-crypttests \
  --with-liboqs="$LIBOQS_PREFIX" \
  CFLAGS="-O2"
make -j"$(nproc)"
make install
echo "== wolfSSL $WOLFSSL_VER (+liboqs) installed to $WOLFSSL_PREFIX =="
grep LIBWOLFSSL_VERSION_STRING "$WOLFSSL_PREFIX/include/wolfssl/version.h"

echo
echo "Smoke test (run from $SRC/wolfssl-$WOLFSSL_VER-oqs, examples stay in the source tree):"
echo "  export LD_LIBRARY_PATH=$LIBOQS_PREFIX/lib:$WOLFSSL_PREFIX/lib:\$LD_LIBRARY_PATH"
echo "  examples/server/server -v 4 --pqc KYBER_LEVEL3 -p 11111 -c certs/server-cert.pem -k certs/server-key.pem -d &"
echo "  sleep 1 && examples/client/client -v 4 --pqc KYBER_LEVEL3 -p 11111 -h 127.0.0.1 -d"
echo "  (note: -d skips cert verification — full Dilithium-signed mutual auth needs the PQ cert"
echo "   chain from row 7, not built yet; -c/-k use wolfSSL's bundled classical test cert for now)"
