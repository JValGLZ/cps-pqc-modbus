#!/usr/bin/env bash
# Multi-session experiment (tracker row 13): one master polls N slaves every cycle, for N = 1 2 4 8 16,
# with persistent sessions and with a new connection (+ handshake) per poll.
#
#   harness/run_multi.sh                          # C0, local slaves, full counts (~17 min)
#   QUICK=1 harness/run_multi.sh                  # ~3.5 min smoke run
#   COND=c1 KEM=p256 SIG=ecdsa-p256 CERTS=certs/out/ecdsa-p256 harness/run_multi.sh
#   COND=c2 KEM=kyber768 SIG=dilithium3 CERTS=certs/out/dilithium3 harness/run_multi.sh
#   HOST=192.168.1.50 harness/run_multi.sh        # slaves already started on that machine (slaves.sh start 16)
#   NS="1 4 16" SESSIONS=persistent PERIOD=10 harness/run_multi.sh
set -euo pipefail
cd "$(dirname "$0")/.."

COND=${COND:-c0}; KEM=${KEM:-}; SIG=${SIG:-}; CERTS=${CERTS:-}
HOST=${HOST:-127.0.0.1}; BASEPORT=${BASEPORT:-1600}; PERIOD=${PERIOD:-100}
NS=${NS:-"1 2 4 8 16"}; SESSIONS=${SESSIONS:-"persistent per-poll"}; PHASE=${PHASE:-P2}
QUICK=${QUICK:-0}; COUNT=${COUNT:-$([ "$QUICK" = 1 ] && echo 200 || echo 1000)}
SENSOR=${SENSOR:-}; CLIENT_CPU=${CLIENT_CPU:-3}; EXTRA=${EXTRA:-}

tls=(); [ -n "$KEM" ] && tls+=(--kem "$KEM"); [ -n "$CERTS" ] && tls+=(--certs "$CERTS")
sig=(); [ -n "$SIG" ] && sig+=(--sig "$SIG")
pin=(); [ "$(nproc)" -ge 4 ] && pin=(--cpu "$CLIENT_CPU")
maxn=0; for n in $NS; do [ "$n" -gt "$maxn" ] && maxn=$n; done

local_slaves=0
if [ "$HOST" = 127.0.0.1 ] || [ "$HOST" = localhost ]; then
  sens=(); [ -n "$SENSOR" ] && sens=(--sensor "$SENSOR")
  harness/slaves.sh start "$maxn" "$BASEPORT" --cond "$COND" "${tls[@]}" "${sens[@]}"
  local_slaves=1
  trap 'harness/slaves.sh stop >/dev/null' EXIT
fi

for s in $SESSIONS; do
  for n in $NS; do
    echo "== $COND ${KEM:-plain} slaves=$n period=${PERIOD}ms cycles=$COUNT session=$s"
    ./bin/mb_poll --host "$HOST" --port "$BASEPORT" --nservers "$n" --cond "$COND" "${tls[@]}" "${sig[@]}" \
       --period-ms "$PERIOD" --count "$COUNT" --session "$s" --phase "$PHASE" "${pin[@]}" $EXTRA \
       2>&1 | grep -E "^mb_poll|cycle ms|connect|RSS|misses|csv"
  done
done
