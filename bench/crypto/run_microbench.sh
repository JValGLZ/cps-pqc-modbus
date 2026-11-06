#!/usr/bin/env bash
# Row 5: build and run the KEM/DSA microbenchmark, then print the summary table.
#   bench/crypto/run_microbench.sh                    # 30 runs x 1000 iters, pinned to CPU 2 (~3-5 min)
#   RUNS=3 ITERS=100 bench/crypto/run_microbench.sh   # quick check
set -euo pipefail
cd "$(dirname "$0")/../.."
LIBOQS_PREFIX=${LIBOQS_PREFIX:-$HOME/pqc/install/liboqs-0.8.0}
WOLFSSL_PREFIX=${WOLFSSL_PREFIX:-$HOME/pqc/install/wolfssl-5.6.3-oqs}
RUNS=${RUNS:-30} ITERS=${ITERS:-1000} CPU=${CPU:-2}

mkdir -p bin
gcc -O2 -Wall -Wextra -o bin/kem_dsa_bench bench/crypto/kem_dsa_bench.c \
  -I"$WOLFSSL_PREFIX/include" -I"$LIBOQS_PREFIX/include" \
  -L"$WOLFSSL_PREFIX/lib" -L"$LIBOQS_PREFIX/lib" -lwolfssl -loqs \
  -Wl,-rpath,"$WOLFSSL_PREFIX/lib" -Wl,-rpath,"$LIBOQS_PREFIX/lib" -Wl,--disable-new-dtags

host=$(hostname)$(grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease && echo -wsl2 || true)
dir=results/raw/$host/$(date +%F)
mkdir -p "$dir"
out=$dir/MICRO-kem-dsa-$(date +%H%M%S).csv
bin/kem_dsa_bench --runs "$RUNS" --iters "$ITERS" --cpu "$CPU" --out "$out"
python3 bench/crypto/summarize_micro.py "$out"
