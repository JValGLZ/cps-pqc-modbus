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
REPO=$(cd "$(dirname "$0")/.." && pwd)
WOLFSSL_PATCH="$REPO/patches/wolfssl-$WOLFSSL_VER-oqs.patch"
[ -f "$WOLFSSL_PATCH" ] || { echo "missing $WOLFSSL_PATCH" >&2; exit 1; }

# Debian/Ubuntu keep libcrypto in a per-architecture folder (x86_64-linux-gnu on the PCs,
# aarch64-linux-gnu on the Pi). Ask the compiler which one this machine uses.
MULTIARCH=$(gcc -print-multiarch 2>/dev/null || dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)
SSL_LIBDIR=/usr/lib/$MULTIARCH
[ -n "$MULTIARCH" ] && [ -e "$SSL_LIBDIR/libcrypto.so" ] || SSL_LIBDIR=/usr/lib
[ -e "$SSL_LIBDIR/libcrypto.so" ] || { echo "libcrypto.so not found (install libssl-dev)" >&2; exit 1; }
echo "== OpenSSL libs: $SSL_LIBDIR =="
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
# multiarch path for libcrypto, even with libssl-dev installed.
cmake -GNinja -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX="$LIBOQS_PREFIX" \
  -DOPENSSL_ROOT_DIR=/usr \
  -DOPENSSL_CRYPTO_LIBRARY="$SSL_LIBDIR/libcrypto.so" \
  -DOPENSSL_SSL_LIBRARY="$SSL_LIBDIR/libssl.so" \
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

# Apply our wolfSSL patch (patches/wolfssl-5.6.3-oqs.patch) before configuring. It covers:
#  - MAX_ENCODED_SIG_SZ too small for Dilithium signatures (asn.h)
#  - Dilithium support in EncodePublicKey, needed to issue Dilithium certs (asn.c)
#  - SPHINCS+ glue using liboqs's pre-0.8.0 "sphincs_shake256_*" names (sphincs.c/.h);
#    this used to be a sed here, now it's part of the patch
# Safe to rerun: skipped if already applied. A tree from the old sed-only script gets the two
# sphincs files restored to stock first, since the patch makes the same change.
if git apply --reverse --check "$WOLFSSL_PATCH" 2>/dev/null; then
  echo "== wolfSSL patch already applied =="
else
  if ! git apply --check "$WOLFSSL_PATCH" 2>/dev/null; then
    git checkout -- wolfssl/wolfcrypt/sphincs.h wolfcrypt/src/sphincs.c
  fi
  git apply "$WOLFSSL_PATCH"
  echo "== wolfSSL patch applied =="
fi

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
echo "Next, from the repo root:"
echo "  certs/make_dilithium_certs.sh"
echo "  make clean && make TLS=1 WOLFSSL_PREFIX=$WOLFSSL_PREFIX OQS_PREFIX=$LIBOQS_PREFIX"
