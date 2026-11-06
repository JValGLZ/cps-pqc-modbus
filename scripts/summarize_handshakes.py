#!/usr/bin/env python3
"""Summarize TLS handshake latency ("connect" = TCP connect + TLS handshake) into Table 8.

Per (host, condition, kem, sig): pooled n, p50, p95, p99 over every handshake, plus the mean and
std of the per-run medians (the paper's 30-run method: one median per run, then mean +/- std).
Only single-slave rows count (n_servers absent or 1), and only measured cycles (trial >= 1).

  scripts/summarize_handshakes.py                    # phase HS30 (scripts/run_handshake_batch.sh)
  scripts/summarize_handshakes.py --phase handshake  # the first 2026-11-05 runs
  scripts/summarize_handshakes.py --phase P2 --host JhonnyPC-wsl2
  scripts/summarize_handshakes.py --phase LINK --metric ttfr   # emulated links (scripts/run_link_sweep.sh)

--metric connect (default): TCP connect + TLS handshake as the client sees it.
--metric ttfr: time to first Modbus response = connect + that cycle's poll_rtt. Use this on slow links:
the client finishes its handshake before its own certificate flight has crossed the link, so the
first request queues behind it and connect alone undercounts.
"""
import argparse, csv, glob, os, re, statistics, sys
from collections import defaultdict


def pct(xs, p):
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def note(notes, k):
    for kv in notes.split(";"):
        if kv.startswith(k + "="):
            return kv.split("=", 1)[1]
    return ""


def single_slave(notes):
    for kv in notes.split(";"):
        if kv.startswith("n_servers="):
            return kv == "n_servers=1"
    return True


ap = argparse.ArgumentParser()
ap.add_argument("--phase", default="HS30", help="phase label to include (default HS30)")
ap.add_argument("--host")
ap.add_argument("--date")
ap.add_argument("--root", default="results/raw")
ap.add_argument("--out", default=None, help="CSV path (default results/summary/table8_<phase>_<metric>.csv)")
ap.add_argument("--metric", choices=["connect", "ttfr"], default="connect")
a = ap.parse_args()
a.out = a.out or f"results/summary/table8_{a.phase}_{a.metric}.csv"

pat = os.path.join(a.root, a.host or "*", a.date or "*", "*.csv")
pooled = defaultdict(list)
per_run = defaultdict(lambda: defaultdict(list))
for path in glob.glob(pat):
    conn, rtt, keys = {}, {}, {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("phase") != a.phase or r.get("op") not in ("connect", "poll_rtt"):
                continue
            if r.get("trial") == "0" or not single_slave(r.get("notes", "")):
                continue
            t = (r["run_id"], r["trial"])
            (conn if r["op"] == "connect" else rtt)[t] = float(r["value"])
            keys[t] = (r["host"], note(r.get("notes", ""), "link"), r["condition"], r["kem"], r["sig"])
    for t, c in conn.items():
        if a.metric == "ttfr":
            if t not in rtt:
                continue
            c += rtt[t]
        pooled[keys[t]].append(c)
        per_run[keys[t]][t[0]].append(c)

if not pooled:
    sys.exit(f"no '{a.phase}' connect rows under {pat}")

order = {"C0": 0, "C1": 1, "C2": 2, "C3": 3}
rows = []
def level(name):
    d = re.findall(r"\d+", name or "")
    return int(d[-1]) if d else 0


links = {"": 0, "lan": 1, "wan": 2, "cell": 3, "serial115k": 4}
for key in sorted(pooled, key=lambda k: (k[0], links.get(k[1], 9), order.get(k[2], 9), level(k[4]), level(k[3]), k[3])):
    xs = pooled[key]
    meds = [statistics.median(v) for v in per_run[key].values()]
    rows.append(dict(host=key[0], link=key[1], condition=key[2], kem=key[3], sig=key[4], runs=len(meds), n=len(xs),
                     p50=pct(xs, 50), p95=pct(xs, 95), p99=pct(xs, 99),
                     run_median_mean=statistics.mean(meds),
                     run_median_std=statistics.stdev(meds) if len(meds) > 1 else 0.0,
                     mean=statistics.mean(xs)))

os.makedirs(os.path.dirname(a.out), exist_ok=True)
with open(a.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    for r in rows:
        w.writerow({k: f"{v:.4f}" if isinstance(v, float) else v for k, v in r.items()})

what = "TCP connect + TLS 1.3 handshake" if a.metric == "connect" else "time to first Modbus response (connect + first poll)"
print(f"Handshake latency (ms), phase {a.phase}: {what}, per-poll, 1 slave\n")
show_link = any(r["link"] for r in rows)
lk = "Link | " if show_link else ""
print(f"| Host | {lk}Cond | KEM | Signature | runs | n | p50 | p95 | p99 | run-median mean ± std |")
print("|---|" + ("---|" if show_link else "") + "---|---|---|---|---|---|---|---|---|")
for r in rows:
    lv = f"{r['link']} | " if show_link else ""
    print(f"| {r['host']} | {lv}{r['condition']} | {r['kem']} | {r['sig']} | {r['runs']} | {r['n']} | "
          f"{r['p50']:.3f} | {r['p95']:.3f} | {r['p99']:.3f} | "
          f"{r['run_median_mean']:.3f} ± {r['run_median_std']:.3f} |")
print(f"\nwritten: {a.out}")
