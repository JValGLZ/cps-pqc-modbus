#!/usr/bin/env bash
# Handshake latency over emulated links (scripts/link_emu.py), the stand-in for tc netem on WSL2.
#
# Profiles are name:one_way_delay_ms:rate_kbps. Defaults cover the cases the report argues about:
#   lan        0.25 ms, 100 Mbps    plant-floor Ethernet
#   wan        25 ms, 10 Mbps       remote site / VPN (50 ms RTT)
#   cell       40 ms, 2 Mbps        cellular modem RTU (80 ms RTT)
#   serial115k 2 ms, 115.2 kbps     serial-to-Ethernet bridge / licensed radio
#
#   scripts/run_link_sweep.sh                       # ~15 min
#   COUNT=5 PROFILES="wan:25:10000" scripts/run_link_sweep.sh
#   scripts/summarize_handshakes.py --phase LINK    # rows per profile are told apart by run_id/notes
set -euo pipefail
cd "$(dirname "$0")/.."
COUNT=${COUNT:-20}
SPORT=${SPORT:-15041}
LPORT=${LPORT:-15040}
PROFILES=${PROFILES:-"lan:0.25:100000 wan:25:10000 cell:40:2000 serial115k:2:115.2"}
PAIRS=${PAIRS:-"c1:x25519:ecdsa-p256 c1:p256:ecdsa-p256 c2:kyber512:dilithium2 c2:kyber768:dilithium3
c2:kyber1024:dilithium5 c3:p256_kyber512:dilithium2"}
certdir() { echo certs/out/$1; }

STAMP=$(date +%H%M%S)
# record which wolfSSL build the binaries use (generic vs SP=1 optimized ECC) in every row
WOLF=$(ldd bin/mb_poll | awk '/libwolfssl/{print $3}'); WOLF=$(basename "$(dirname "$(dirname "$WOLF")")")
TMP=$(mktemp -d)
cleanup() { pkill -f "link_emu.py --listen $LPORT" 2>/dev/null || true
            pkill -f "mb_server --port $SPORT" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

for prof in $PROFILES; do
  IFS=: read -r name delay rate <<<"$prof"
  # period must exceed the slowest handshake on this link: flights of ~30 KB at the given rate + RTTs
  period=$(python3 -c "print(max(100, int(30000*8/($rate*1000)*1000 + 8*$delay + 100)))")
  python3 scripts/link_emu.py --listen "$LPORT" --target "127.0.0.1:$SPORT" --delay-ms "$delay" \
    --rate-kbps "$rate" >/dev/null &
  emu=$!
  sleep 0.5
  echo "== $name: one-way ${delay} ms, ${rate} kbps, period ${period} ms =="
  for p in $PAIRS; do
    IFS=: read -r cond kem sig <<<"$p"
    bin/mb_server --port "$SPORT" --cond "$cond" --kem "$kem" --sig "$sig" --certs "$(certdir "$sig")" \
      --quiet >/dev/null 2>&1 &
    srv=$!
    sleep 0.5
    rid="LINK-$name-${cond^^}-$kem-$sig-$STAMP"
    if timeout 900 bin/mb_poll --host 127.0.0.1 --port "$LPORT" --cond "$cond" --kem "$kem" --sig "$sig" \
         --certs "$(certdir "$sig")" --session per-poll --count "$COUNT" --warmup 2 --period-ms "$period" \
         --timeout-ms 30000 --phase LINK --run-id "$rid" \
         --notes "link=$name;delay_ms=$delay;rate_kbps=$rate;wolfssl=$WOLF" --results-dir "$TMP" >"$TMP/log" 2>&1; then
      printf "  %-3s %-14s %-11s %s\n" "$cond" "$kem" "$sig" "$(grep -oE 'connect +n=[0-9]+ mean [0-9.]+ ms' "$TMP/log")"
    else
      printf "  %-3s %-14s %-11s FAILED: %s\n" "$cond" "$kem" "$sig" "$(tail -1 "$TMP/log")"
    fi
    kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null || true
  done
  kill "$emu" 2>/dev/null; wait "$emu" 2>/dev/null || true
done

for f in $(find "$TMP" -name "LINK-*.csv"); do
  rel=$(dirname "$f"); rel=${rel#"$TMP"/}; mkdir -p "results/raw/$rel"; mv "$f" "results/raw/$rel/"
done
echo "== CSVs in results/raw/<host>/$(date +%F)/LINK-*-$STAMP.csv =="
