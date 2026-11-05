# Harness: multi-session master and sensor slaves

## Multi-session experiment (tracker row 13)

One master (`mb_poll`, the PC) polls N slaves (`mb_server`, each a separate process and port) once per cycle.
Within a cycle the slaves are polled one after another. The cycle time is measured from the release time to the
last slave's answer, and it is what the deadline is judged on.

```bash
QUICK=1 harness/run_multi.sh                                   # C0, N = 1 2 4 8 16, persistent + per-poll (~4 min)
QUICK=1 COND=c1 KEM=p256 SIG=ecdsa-p256 CERTS=certs/out/ecdsa-p256 harness/run_multi.sh
COND=c2 KEM=kyber768 SIG=dilithium3 CERTS=certs/out/dilithium3 harness/run_multi.sh   # full counts (~17 min)
python3 harness/summarize.py "results/raw/**/*.csv"            # n, cycle_p50_ms, connect_all_ms, rss_end_kb columns
```

Knobs: `NS="1 4 16"`, `SESSIONS=persistent`, `PERIOD=10`, `COUNT=...`, `BASEPORT=1600`, `SENSOR=fake`.

New CSV rows (same schema; `notes` carries `n_servers` and, for per-slave rows, `server=i`):

| `op` | value | meaning |
| --- | --- | --- |
| `poll_rtt` | ms | one slave: request sent → response received |
| `poll_resp` | ms | one cycle: release → last slave answered (`miss`, `nfail` in notes) |
| `connect` | ms | one slave's TCP connect + TLS handshake |
| `connect_all` | ms | connecting every slave at startup, back to back (the "everything reconnects" case) |
| `master_rss_kb` | kB | master memory: `stage=before_connect`, `all_connected`, `end` |

With N = 1 the output is the same as before, so the earlier C0/C1 runs stay comparable.

### Slaves on another machine (the Pi)

```bash
# on the Pi
harness/slaves.sh start 16 1600 --cond c2 --kem kyber768 --certs certs/out/dilithium3 --sensor fake
# on the PC
HOST=<pi-ip> BASEPORT=1600 COND=c2 KEM=kyber768 SIG=dilithium3 CERTS=certs/out/dilithium3 harness/run_multi.sh
# on the Pi, afterwards
harness/slaves.sh stop
```

## Sensor (tracker row 11)

`mb_server --sensor fake` samples a simulated temperature (about 22.5 °C ± 2) every `--sample-ms` (default 1000)
in its own thread. It stores `round(reading × 10)` in register 1 and a sample counter in register 2. Modbus requests
are answered from those stored values, so a slow sensor never adds to the measured poll time.

For the real sensor on the Pi, have any script write the latest reading to a file and point the server at it:

```bash
python3 read_my_sensor.py --out /run/user/$(id -u)/sensor.txt &      # writes e.g. "23.4" every second
./bin/mb_server --port 1600 --cond c2 ... --sensor file:/run/user/$(id -u)/sensor.txt
```

Options: `--sensor-reg R` (default 1), `--sensor-scale X` (default 10), `--sample-ms N`.
Run `tests/pymodbus_check.py` against a server *without* `--sensor`, since it expects the default register values.
