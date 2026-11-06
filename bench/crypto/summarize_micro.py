#!/usr/bin/env python3
"""Row 5 table: mean +/- std (across runs) of us/op per primitive, from kem_dsa_bench CSVs.
Usage: bench/crypto/summarize_micro.py FILE.csv [...]   (or a glob like "results/raw/**/MICRO-*.csv")"""
import csv, glob, os, statistics, sys
from collections import defaultdict

files = [f for a in sys.argv[1:] for f in (glob.glob(a, recursive=True) or [a])]
if not files:
    sys.exit(__doc__)
vals, size, notes = defaultdict(list), {}, {}
for path in files:
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r["phase"] != "MICRO":
                continue
            key = (r["host"], r["op"])
            vals[key].append(float(r["value"]))
            if r["bytes"]:
                size[key] = r["bytes"]
            notes[r["host"]] = ";".join(kv for kv in r["notes"].split(";") if not kv.startswith("iters="))

rows = []
for (host, op), xs in vals.items():
    alg, _, what = op.rpartition("-")
    rows.append(dict(host=host, alg=alg, op=what, runs=len(xs), mean_us=statistics.mean(xs),
                     std_us=statistics.stdev(xs) if len(xs) > 1 else 0.0, bytes=size.get((host, op), "")))
order = ["kyber512", "kyber768", "kyber1024", "x25519", "p256", "dilithium2", "dilithium3", "dilithium5", "ecdsa-p256"]
ops = ["keygen", "encaps", "decaps", "derive", "sign", "verify"]
rows.sort(key=lambda r: (r["host"], order.index(r["alg"]) if r["alg"] in order else 99, ops.index(r["op"]) if r["op"] in ops else 99))

out = "results/summary/table_micro_kem_dsa.csv"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    for r in rows:
        w.writerow({k: f"{v:.3f}" if isinstance(v, float) else v for k, v in r.items()})

host = None
for r in rows:
    if r["host"] != host:
        host = r["host"]
        print(f"\n{host}  ({notes.get(host, '')})\n")
        print("| Algorithm | Operation | runs | mean (µs/op) | std | size (B) |")
        print("|---|---|---|---|---|---|")
    print(f"| {r['alg']} | {r['op']} | {r['runs']} | {r['mean_us']:.2f} | {r['std_us']:.2f} | {r['bytes']} |")
print(f"\nwritten: {out}")
