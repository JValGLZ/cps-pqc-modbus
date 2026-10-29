# PQC Modbus/TCP testbed

Cyber Physical Systems (UTEP, Fall 2026) — Jhonny Gonzalez, Jose Gonzalez.
Modbus/TCP over plain TCP (C0), classical TLS 1.3 (C1), and post-quantum TLS 1.3 (C2/C3), measured under a strict
repeating polling deadline.

## Quick start (WSL2 Ubuntu or native Linux)

Work inside the Linux filesystem (`~/...`), not under `/mnt/c/...`, which is much slower in WSL2.

```bash
sudo apt update && sudo apt install -y build-essential git autoconf automake libtool bsdextrautils python3-venv openssl
python3 -m venv ~/.venvs/cps && . ~/.venvs/cps/bin/activate && pip install pymodbus

make                                         # builds bin/mb_server and bin/mb_poll (C0 only, no deps)

./bin/mb_server --port 1502 &                # C0 server (field device)
python3 tests/pymodbus_check.py --port 1502  # independent Modbus client must print PASS
./bin/mb_poll --period-ms 100 --count 1000   # 1000 polls at 100 ms, CSV under results/raw/<host>/<date>/
kill %1

QUICK=1 harness/run_sweep.sh                 # ~30 s smoke sweep at 1000/100/10/3 ms
harness/run_sweep.sh                         # full sweep (~13 min): 300/3000/10000/20000 polls
python3 harness/summarize.py "results/raw/**/*.csv"
```

## C1: Modbus over classical TLS 1.3

```bash
stack/build_wolfssl_classic.sh               # stock wolfSSL 5.6.3 -> ~/pqc/install/wolfssl-5.6.3 (~1 min)
certs/make_classical_certs.sh                # ECDSA P-256 CA + server + client certs -> certs/out/ecdsa-p256/
make clean && make TLS=1                     # same binaries, now TLS-capable (C0 still works)

COND=c1 KEM=p256 SIG=ecdsa-p256 CERTS=certs/out/ecdsa-p256 QUICK=1 harness/run_sweep.sh
COND=c1 KEM=p256 SIG=ecdsa-p256 CERTS=certs/out/ecdsa-p256 SESSION=per-poll PERIODS="1000 100" harness/run_sweep.sh
```

TLS settings match Shahid et al.: TLS 1.3 only, `TLS13-AES256-GCM-SHA384`. Both sides present certificates (mutual
auth, as in the Modbus/TCP Security spec). The client sends a key share for exactly the `--kem` group, and the server
accepts only that group, so a mismatch fails loudly instead of silently negotiating something else.

## C2/C3: post-quantum (Jose's stack)

Build wolfSSL 5.6.3 `--with-liboqs` (liboqs 0.8.0) to its own prefix, put Dilithium chains in `certs/out/<sig>/` with
the same file names, then:

```bash
make clean && make TLS=1 WOLFSSL_PREFIX=$HOME/pqc/install/wolfssl-5.6.3-oqs
COND=c2 KEM=kyber768 SIG=dilithium3 CERTS=certs/out/dilithium3 QUICK=1 harness/run_sweep.sh
COND=c3 KEM=p256_kyber512 SIG=dilithium2 CERTS=certs/out/dilithium2 QUICK=1 harness/run_sweep.sh
```

`--kem` names: `p256 p384 p521 x25519` (any build); `kyber512 kyber768 kyber1024 p256_kyber512 p384_kyber768
p521_kyber1024` (liboqs build only; these map to wolfSSL 5.6.3's `WOLFSSL_KYBER_LEVEL*` groups).

## What gets measured

`mb_poll` wakes at absolute release times `r_k = t0 + k·period` (`clock_nanosleep` + `TIMER_ABSTIME`, so the schedule
never drifts), sends one request, and waits for the reply. Everything is timed on the client's own clock. Results are
buffered and written after the run, so there's no file I/O in the timed loop.

| `op` in CSV | value | meaning |
| --- | --- | --- |
| `poll_rtt` | ms | request sent → response received |
| `poll_resp` | ms | release time → response received; `miss=1` in notes if over the deadline or failed |
| `connect` | ms | TCP connect + TLS handshake (once per run, or every poll with `--session per-poll`) |

`notes` also carries `period_ms`, `deadline_ms`, `session`, `status` (0 = OK, >0 = Modbus exception), and
`wake_late_us` (how late the OS woke us — the jitter floor). Rows follow the shared schema:
`run_id,host,phase,condition,kem,sig,op,trial,value,unit,bytes,notes,timestamp`.

Measure C0 first: its misses and `wake_late` are the floor. Count a miss as crypto-caused only above that floor.

## WSL2 notes

- The host field gets a `-wsl2` suffix automatically; WSL2 is a VM, so treat timings as VM timings.
- Set Windows power mode to **Best performance** before timing runs; close heavy apps.
- `scripts/machine_info.sh` prints a `docs/machines.md` entry for the current machine.
- For the desktop-to-desktop LAN sweep, WSL2's default NAT hides the server from the LAN. On Windows 11, add
  `[wsl2]` / `networkingMode=mirrored` to `%UserProfile%\.wslconfig`, run `wsl --shutdown`, and allow the port
  in Windows Firewall. Or run the LAN tests from a native Linux boot.

## Layout and owners

| Path | Owner | Contents |
| --- | --- | --- |
| `modbus/` | Jhonny | Modbus/TCP framing (`modbus.c`) and server (`mb_server.c`) |
| `harness/` | Jhonny | polling client (`mb_poll.c`), sweep runner, summary script |
| `transport/` | shared | `transport.h` interface; C0 + TLS (C1) implemented, Jose extends for C2/C3 |
| `stack/` | Jose | pinned build scripts (`build_wolfssl_classic.sh` is the C1 starter) |
| `certs/` | Jose | cert-chain scripts (`make_classical_certs.sh` is the C1 starter) |
| `bench/crypto/`, `analysis/` | Jose | KEM/DSA/handshake replication, figures |
| `tests/` | Jhonny | `pymodbus_check.py` interop test |
| `results/raw/<host>/<date>/` | both | CSV output only, never hand-edited |
