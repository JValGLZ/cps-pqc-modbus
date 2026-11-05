#!/usr/bin/env bash
# Start / stop N Modbus slaves (mb_server processes) on consecutive ports, one per simulated field device.
#
#   harness/slaves.sh start 16                    # C0 slaves on ports 1600..1615
#   harness/slaves.sh start 16 1600 --cond c1 --kem p256 --certs certs/out/ecdsa-p256
#   harness/slaves.sh start 8 1600 --sensor fake  # each slave also samples a (fake) sensor
#   harness/slaves.sh status
#   harness/slaves.sh stop
#
# On the Pi: run "start" there, then poll from the PC with
#   ./bin/mb_poll --host <pi-ip> --port 1600 --nservers 16 ...
# Ports below 1024 (e.g. 802, the Modbus/TCP Security port) need sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
PIDFILE=${PIDFILE:-${XDG_RUNTIME_DIR:-/tmp}/mb_slaves.$(id -u).pids}

wait_listening() {   # port: wait up to 3 s for a listener (uses ss if present)
  command -v ss >/dev/null || { sleep 0.3; return 0; }
  for _ in $(seq 30); do ss -ltn "sport = :$1" | grep -q LISTEN && return 0; sleep 0.1; done
  return 1
}

case ${1:-} in
  start)
    n=${2:?usage: slaves.sh start N [BASEPORT] [mb_server args...]}; base=${3:-1600}; shift $(( $# >= 3 ? 3 : 2 ))
    [ -s "$PIDFILE" ] && { echo "slaves already running (harness/slaves.sh stop first)"; exit 1; }
    : > "$PIDFILE"
    for i in $(seq 0 $((n - 1))); do
      ./bin/mb_server --port $((base + i)) --quiet "$@" 2>>"${PIDFILE%.pids}.log" &
      echo $! >> "$PIDFILE"
    done
    for i in $(seq 0 $((n - 1))); do wait_listening $((base + i)) || { echo "slave on port $((base + i)) did not start (see ${PIDFILE%.pids}.log)"; exit 1; }; done
    echo "started $n slaves on ports $base..$((base + n - 1))" ;;
  stop)
    [ -f "$PIDFILE" ] || { echo "no slaves running"; exit 0; }
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "$PIDFILE"
    sleep 0.3; rm -f "$PIDFILE"; echo "stopped" ;;
  status)
    [ -f "$PIDFILE" ] || { echo "no slaves running"; exit 0; }
    alive=0; while read -r pid; do kill -0 "$pid" 2>/dev/null && alive=$((alive + 1)); done < "$PIDFILE"
    echo "$alive / $(wc -l < "$PIDFILE") slaves alive" ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
