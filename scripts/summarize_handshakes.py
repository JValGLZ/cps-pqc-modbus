#!/usr/bin/env python3
"""Summarize TLS handshake latency (op=connect, phase=handshake) from
results/raw/**/*.csv into Table 8: mean/std/p50/p95/p99 per (cond,kem,sig).
Usage: scripts/summarize_handshakes.py [--host HOST] [--date YYYY-MM-DD]"""
import csv, glob, os, sys, statistics, argparse
from collections import defaultdict

def pct(xs, p):
    xs = sorted(xs)
    if len(xs) == 1: return xs[0]
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

ap = argparse.ArgumentParser()
ap.add_argument("--host"); ap.add_argument("--date")
ap.add_argument("--root", default="results/raw")
a = ap.parse_args()

pat = os.path.join(a.root, a.host or "*", a.date or "*", "*.csv")
data, runs = defaultdict(list), defaultdict(set)
for path in glob.glob(pat):
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("phase") != "handshake" or r.get("op") != "connect":
                continue
            key = (r["condition"], r["kem"], r["sig"])
            data[key].append(float(r["value"]))
            runs[key].add(r["run_id"])

if not data:
    sys.exit(f"no handshake rows found under {pat}")

rows = []
for key in sorted(data):
    xs = data[key]
    rows.append(dict(condition=key[0], kem=key[1], sig=key[2], n=len(xs),
        runs=len(runs[key]), mean=statistics.mean(xs),
        std=statistics.stdev(xs) if len(xs) > 1 else 0.0,
        p50=pct(xs, 50), p95=pct(xs, 95), p99=pct(xs, 99), max=max(xs)))

out = "results/summary/table8_handshake.csv"
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    for r in rows:
        w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})

print("| Cond | KEM | Signature | n | runs | Mean (ms) | Std | p50 | p95 | p99 |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    print(f"| {r['condition']} | {r['kem']} | {r['sig']} | {r['n']} | {r['runs']} | "
          f"{r['mean']:.3f} | {r['std']:.3f} | {r['p50']:.3f} | {r['p95']:.3f} | {r['p99']:.3f} |")
print(f"\nwritten: {out}")
