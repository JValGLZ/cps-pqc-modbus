#!/usr/bin/env bash
# Table 8 handshake batch: RUNS repetitions of COUNT fresh handshakes per (cond, kem, sig).
#
# Measurement standard (agree with Jhonny before comparing machines):
#   --session per-poll, one slave (N=1), --period-ms 50, client and server pinned to their own CPU,
#   phase label HS30. "connect" = TCP connect + TLS 1.3 handshake, timed on the client.
#   Report pooled p50/p95 plus mean +/- std of the per-run medians (the paper's 30-run method).
#
# Runs are interleaved (run 1 of every pair, then run 2 of every pair, ...) so slow drift on the
# machine (thermal, background load) spreads across all pairs instead of biasing one of them.
#
#   scripts/run_handshake_batch.sh                  # 30 runs x 100 handshakes x 14 pairs, ~50 min
#   RUNS=2 COUNT=10 scripts/run_handshake_batch.sh  # quick check, ~1 min
#   PAIRS="c1:x25519:ecdsa-p256 c2:kyber768:dilithium3" scripts/run_handshake_batch.sh
#
# Output: one CSV per pair, results/raw/<host>/<date>/HS30-<cond>-<kem>-<sig>-<stamp>.csv
# (all runs in one file; run_id tells the runs apart). Summarize with:
#   scripts/summarize_handshakes.py --phase HS30
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS=${RUNS:-30}
COUNT=${COUNT:-100}
WARMUP=${WARMUP:-10}
PERIOD=${PERIOD:-50}
PORT=${PORT:-15030}
SRV_CPU=${SRV_CPU:-2}
CLI_CPU=${CLI_CPU:-3}
PHASE=${PHASE:-HS30}
PAIRS=${PAIRS:-"c1:x25519:ecdsa-p256 c1:p256:ecdsa-p256
c2:kyber512:dilithium2 c2:kyber768:dilithium2 c2:kyber1024:dilithium2
c2:kyber512:dilithium3 c2:kyber768:dilithium3 c2:kyber1024:dilithium3
c2:kyber512:dilithium5 c2:kyber768:dilithium5 c2:kyber1024:dilithium5
c3:p256_kyber512:dilithium2 c3:p384_kyber768:dilithium3 c3:p521_kyber1024:dilithium5"}

certdir() { case $1 in ecdsa-p256) echo certs/out/ecdsa-p256 ;; *) echo certs/out/$1 ;; esac; }

for p in $PAIRS; do
  IFS=: read -r cond kem sig <<<"$p"
  [ -f "$(certdir "$sig")/ca.pem" ] || { echo "missing certs for $sig in $(certdir "$sig")" >&2; exit 1; }
done
[ -x bin/mb_server ] && [ -x bin/mb_poll ] || { echo "build first: make TLS=1 ..." >&2; exit 1; }

STAMP=$(date +%H%M%S)
# record which wolfSSL build the binaries use (generic vs SP=1 optimized ECC) in every row
WOLF=$(ldd bin/mb_poll | awk '/libwolfssl/{print $3}'); WOLF=$(basename "$(dirname "$(dirname "$WOLF")")")
TMP=$(mktemp -d)
trap 'pkill -f "mb_server --port $PORT" 2>/dev/null || true; rm -rf "$TMP"' EXIT

npairs=$(wc -w <<<"$PAIRS")
echo "== $PHASE ($WOLF): $RUNS runs x $COUNT handshakes x $npairs pairs, period ${PERIOD}ms, cpus srv=$SRV_CPU cli=$CLI_CPU =="
fails=0
for r in $(seq 1 "$RUNS"); do
  for p in $PAIRS; do
    IFS=: read -r cond kem sig <<<"$p"
    cd_=$(certdir "$sig")
    bin/mb_server --port "$PORT" --cond "$cond" --kem "$kem" --sig "$sig" --certs "$cd_" \
      --cpu "$SRV_CPU" --quiet >/dev/null 2>&1 &
    srv=$!
    sleep 0.5
    rid=$(printf "%s-%s-%s-%s-r%02d-%s" "$PHASE" "${cond^^}" "$kem" "$sig" "$r" "$STAMP")
    if ! timeout 300 bin/mb_poll --host 127.0.0.1 --port "$PORT" --cond "$cond" --kem "$kem" --sig "$sig" \
         --certs "$cd_" --session per-poll --count "$COUNT" --warmup "$WARMUP" --period-ms "$PERIOD" \
         --cpu "$CLI_CPU" --phase "$PHASE" --run-id "$rid" --notes "run=$r;std=hs1;wolfssl=$WOLF" \
         --results-dir "$TMP" >"$TMP/last.log" 2>&1; then
      fails=$((fails + 1)); echo "  FAILED: run $r $cond $kem $sig"; tail -3 "$TMP/last.log"
    fi
    kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null || true
  done
  printf "  run %2d/%d done\n" "$r" "$RUNS"
done

# Merge each pair's runs into one CSV under results/raw/<host>/<date>/.
for p in $PAIRS; do
  IFS=: read -r cond kem sig <<<"$p"
  files=$(find "$TMP" -name "$PHASE-${cond^^}-$kem-$sig-r*-$STAMP.csv" | sort)
  [ -n "$files" ] || continue
  rel=$(dirname "$(head -1 <<<"$files")"); rel=${rel#"$TMP"/}
  mkdir -p "results/raw/$rel"
  out="results/raw/$rel/$PHASE-${cond^^}-$kem-$sig-$STAMP.csv"
  { head -1 "$(head -1 <<<"$files")"; for f in $files; do tail -n +2 "$f"; done; } >"$out"
  echo "  wrote $out"
done
echo "== done, $fails failed runs =="
