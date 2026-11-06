#!/usr/bin/env python3
"""Summarize TLS handshake latency ("connect" = TCP connect + TLS handshake) into Table 8.

Per (host, condition, kem, sig): pooled n, p50, p95, p99 over every handshake, plus the mean and
std of the per-run medians (the paper's 30-run method: one median per run, then mean +/- std).
Only single-slave rows count (n_servers absent or 1), and only measured cycles (trial >= 1).

  scripts/summarize_handshakes.py                    # phase HS30 (scripts/run_handshake_batch.sh)
  scripts/summarize_handshakes.py --phase handshake  # the first 2026-11-05 runs
  scripts/summarize_handshakes.py --phase P2 --host JhonnyPC-wsl2
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
ap.add_argument("--out", default="results/summary/table8_handshake.csv")
a = ap.parse_args()

pat = os.path.join(a.root, a.host or "*", a.date or "*", "*.csv")
pooled = defaultdict(list)
per_run = defaultdict(lambda: defaultdict(list))
for path in glob.glob(pat):
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("phase") != a.phase or r.get("op") != "connect":
                continue
            if r.get("trial") == "0" or not single_slave(r.get("notes", "")):
                continue
            key = (r["host"], r["condition"], r["kem"], r["sig"])
            v = float(r["value"])
            pooled[key].append(v)
            per_run[key][r["run_id"]].append(v)

if not pooled:
    sys.exit(f"no '{a.phase}' connect rows under {pat}")

order = {"C0": 0, "C1": 1, "C2": 2, "C3": 3}
rows = []
def level(name):
    d = re.findall(r"\d+", name or "")
    return int(d[-1]) if d else 0


for key in sorted(pooled, key=lambda k: (k[0], order.get(k[1], 9), level(k[3]), level(k[2]), k[2])):
    xs = pooled[key]
    meds = [statistics.median(v) for v in per_run[key].values()]
    rows.append(dict(host=key[0], condition=key[1], kem=key[2], sig=key[3], runs=len(meds), n=len(xs),
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

print(f"Handshake latency (ms), phase {a.phase}: TCP connect + TLS 1.3 handshake, per-poll, 1 slave\n")
print("| Host | Cond | KEM | Signature | runs | n | p50 | p95 | p99 | run-median mean ± std |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    print(f"| {r['host']} | {r['condition']} | {r['kem']} | {r['sig']} | {r['runs']} | {r['n']} | "
          f"{r['p50']:.3f} | {r['p95']:.3f} | {r['p99']:.3f} | "
          f"{r['run_median_mean']:.3f} ± {r['run_median_std']:.3f} |")
print(f"\nwritten: {a.out}")
