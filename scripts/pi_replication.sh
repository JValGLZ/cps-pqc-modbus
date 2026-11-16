#!/usr/bin/env bash
# Row 16: replicate our desktop tables on the Raspberry Pi over loopback (Pi versions of Tables 6-9 inputs).
#   1. KEM/DSA microbenchmarks (bench/crypto/run_microbench.sh)   ~5-10 min on a Pi 3 B+
#   2. HS30 handshake batch (scripts/run_handshake_batch.sh)     ~50 min
# while logging CPU temperature and throttling every 5 s (the Pi 3 B+ slows itself down around 60 C).
#
# Run it inside tmux so a dropped SSH/Wi-Fi session doesn't kill it:
#   tmux new -s pirep
#   scripts/pi_replication.sh 2>&1 | tee ~/pi_replication.log
#   (detach: Ctrl-b d   reattach: tmux attach -t pirep)
#
# Quick check first (~3 min):  QUICK=1 scripts/pi_replication.sh
#
# Before starting: tell Jhonny. Nothing else may run on the Pi during this (it shares the CPU).
set -euo pipefail
cd "$(dirname "$0")/.."
OQS=${OQS_PREFIX:-$HOME/pqc/install/liboqs-0.8.0}
WOLF=${WOLFSSL_PREFIX:-$HOME/pqc/install/wolfssl-5.6.3-oqs-sp}
IFACE=${IFACE:-eth0}
if [ "${QUICK:-0}" = 1 ]; then
  MICRO_RUNS=3; MICRO_ITERS=100; HS_RUNS=1; HS_COUNT=10; HS_WARMUP=2
else
  MICRO_RUNS=${MICRO_RUNS:-30}; MICRO_ITERS=${MICRO_ITERS:-1000}; HS_RUNS=${HS_RUNS:-30}; HS_COUNT=${HS_COUNT:-100}; HS_WARMUP=${HS_WARMUP:-10}
fi

# ---- preflight: nothing else running, no leftover netem, optimized build ----
[ -x harness/slaves.sh ] && harness/slaves.sh stop >/dev/null 2>&1 || true
if pgrep -f "bin/mb_(server|poll)" >/dev/null; then
  echo "mb_server/mb_poll processes are running (Jhonny's runs?). Stop them or wait:" >&2
  pgrep -af "bin/mb_(server|poll)" >&2; exit 1
fi
if command -v tc >/dev/null && tc qdisc show dev "$IFACE" 2>/dev/null | grep -q netem; then
  echo "a tc netem rule is active on $IFACE; remove it first: sudo tc qdisc del dev $IFACE root" >&2; exit 1
fi
[ -f "$WOLF/lib/libwolfssl.so" ] || { echo "optimized wolfSSL not found at $WOLF (SP=1 SKIP_LIBOQS=1 stack/build_pqc.sh)" >&2; exit 1; }
for d in ecdsa-p256 dilithium2 dilithium3 dilithium5; do
  [ -f "certs/out/$d/ca.pem" ] || { echo "missing certs/out/$d" >&2; exit 1; }
done
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)
[ "$gov" = performance ] || echo "WARNING: CPU governor is '$gov', not 'performance'" >&2

# Rebuild the Modbus binaries against the optimized build (same as every other host).
make clean >/dev/null && make TLS=1 WOLFSSL_PREFIX="$WOLF" OQS_PREFIX="$OQS" >/dev/null
ldd bin/mb_poll | grep -q "$WOLF/lib" || { echo "bin/mb_poll is not linked against $WOLF" >&2; exit 1; }

host=$(hostname)$(grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease && echo -wsl2 || true)
dir=results/raw/$host/$(date +%F)
mkdir -p "$dir"
stamp=$(date +%H%M%S)

# ---- temperature / throttling log (same format as Jhonny's pi3-temperature-*.txt) ----
templog=$dir/$host-temperature-REPL-$stamp.txt
echo "unix_time,temp_millicelsius,throttled_flags,cpu0_khz" >"$templog"
(
  while true; do
    t=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo NA)
    th=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2 || true); th=${th:-NA}
    f=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo NA)
    echo "$(date +%s),$t,$th,$f" >>"$templog"
    sleep 5
  done
) &
logger=$!
trap 'kill $logger 2>/dev/null || true; pkill -f "mb_server --port 15030" 2>/dev/null || true' EXIT

echo "== Pi replication on $host: governor $gov, wolfSSL $WOLF =="
echo "== 1/2 microbenchmarks: $MICRO_RUNS runs x $MICRO_ITERS ops ($(date +%T)) =="
WOLFSSL_PREFIX="$WOLF" LIBOQS_PREFIX="$OQS" RUNS=$MICRO_RUNS ITERS=$MICRO_ITERS CPU=2 \
  bench/crypto/run_microbench.sh

echo "== 2/2 handshake batch: $HS_RUNS runs x $HS_COUNT handshakes ($(date +%T)) =="
RUNS=$HS_RUNS COUNT=$HS_COUNT WARMUP=$HS_WARMUP SRV_CPU=2 CLI_CPU=3 PHASE=HS30 \
  scripts/run_handshake_batch.sh

kill $logger 2>/dev/null || true
python3 - "$templog" <<'EOF'
import csv, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["temp_millicelsius"] not in ("", "NA")]
if rows:
    t = [int(r["temp_millicelsius"]) / 1000 for r in rows]
    flags = sorted({r["throttled_flags"] for r in rows})
    print(f"temperature: {len(rows)} samples, min {min(t):.1f} C, max {max(t):.1f} C, throttled flags {flags}")
    print("  (0x0 = never throttled; bit 2/0x4 = throttled now, bit 18/0x40000 = throttled since boot, "
          "bit 19/0x80000 = soft temp limit hit since boot)")
EOF
echo
python3 scripts/summarize_handshakes.py --phase HS30 --host "$host" --out "results/summary/table8_HS30_connect_$host.csv"
echo
echo "== done ($(date +%T)). Results in $dir. Commit them with:"
echo "   git add $dir results/summary && git commit -m 'Pi replication on $host: microbenchmarks + HS30' && git push"
