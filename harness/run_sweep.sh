#!/usr/bin/env bash
# Deadline sweep: run mb_poll at several polling periods for one condition.
#
#   harness/run_sweep.sh                         # C0 on loopback, full counts (~13 min)
#   QUICK=1 harness/run_sweep.sh                 # short smoke run (~30 s)
#   COND=c1 KEM=p256 SIG=ecdsa-p256 CERTS=certs/out/ecdsa-p256 harness/run_sweep.sh
#   HOST=192.168.1.50 harness/run_sweep.sh       # remote server already running there (no local server)
#   SESSION=per-poll PERIODS="1000 100" harness/run_sweep.sh
#
# Full counts: 1000 ms x 300, 100 ms x 3000, 10 ms x 10000, 3 ms x 20000 (3 ms = IEC 61850-style stress).
set -euo pipefail
cd "$(dirname "$0")/.."

COND=${COND:-c0}; KEM=${KEM:-}; SIG=${SIG:-}; CERTS=${CERTS:-}
HOST=${HOST:-127.0.0.1}; PORT=${PORT:-1502}; SESSION=${SESSION:-persistent}
PERIODS=${PERIODS:-"1000 100 10 3"}; PHASE=${PHASE:-P0}; QUICK=${QUICK:-0}
SERVER_CPU=${SERVER_CPU:-2}; CLIENT_CPU=${CLIENT_CPU:-3}
EXTRA=${EXTRA:-}   # extra mb_poll flags, e.g. "--rt"

count_for() {
  if [ "$QUICK" = 1 ]; then
    case $1 in 1000) echo 10;; 100) echo 100;; 10) echo 1000;; *) echo 2000;; esac
  else
    case $1 in 1000) echo 300;; 100) echo 3000;; 10) echo 10000;; *) echo 20000;; esac
  fi
}

ncpu=$(nproc)
pin_srv=(); pin_cli=()
if [ "$ncpu" -ge 4 ]; then pin_srv=(--cpu "$SERVER_CPU"); pin_cli=(--cpu "$CLIENT_CPU"); fi

tls=()
[ -n "$KEM" ] && tls+=(--kem "$KEM")
[ -n "$SIG" ] && tls+=(--sig "$SIG")
[ -n "$CERTS" ] && tls+=(--certs "$CERTS")

srv_pid=""
if [ "$HOST" = 127.0.0.1 ] || [ "$HOST" = localhost ]; then
  ./bin/mb_server --port "$PORT" --cond "$COND" "${tls[@]}" "${pin_srv[@]}" --quiet &
  srv_pid=$!
  trap '[ -n "$srv_pid" ] && kill $srv_pid 2>/dev/null || true' EXIT
  sleep 0.5
fi

for p in $PERIODS; do
  n=$(count_for "$p")
  echo "== $COND ${KEM:-plain} period=${p}ms polls=$n session=$SESSION"
  ./bin/mb_poll --host "$HOST" --port "$PORT" --cond "$COND" "${tls[@]}" --period-ms "$p" --count "$n" \
     --session "$SESSION" --phase "$PHASE" "${pin_cli[@]}" $EXTRA
done
