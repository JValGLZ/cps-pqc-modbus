#!/usr/bin/env python3
"""Summarize mb_poll CSVs: one line per run (RTT percentiles, deadline misses, jitter floor, connect time).

    python3 harness/summarize.py results/raw/**/*.csv
    python3 harness/summarize.py results/raw/myhost/2026-10-29/*.csv --csv summary.csv

Standard library only. Percentiles are nearest-rank, matching mb_poll's own summary.
"""
import argparse
import csv
import glob
import math
import statistics
import sys
from collections import OrderedDict


def pct(sorted_vals, p):
    if not sorted_vals:
        return math.nan
    k = max(1, min(len(sorted_vals), math.ceil(p / 100 * len(sorted_vals))))
    return sorted_vals[k - 1]


def notes_dict(s):
    d = {}
    for part in (s or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--csv", help="also write the summary table to this CSV")
    a = ap.parse_args()

    paths = []
    for f in a.files:
        paths.extend(sorted(glob.glob(f, recursive=True)) or [f])

    runs = OrderedDict()
    for p in paths:
        with open(p, newline="") as fh:
            for row in csv.DictReader(fh):
                rid = row["run_id"]
                n = notes_dict(row["notes"])
                r = runs.setdefault(rid, {
                    "run_id": rid, "host": row["host"], "cond": row["condition"], "kem": row["kem"],
                    "sig": row["sig"], "period_ms": n.get("period_ms", ""), "deadline_ms": n.get("deadline_ms", ""),
                    "session": n.get("session", ""), "mb_op": n.get("mb_op", ""), "n": int(n.get("n_servers", "1")),
                    "rtt": [], "resp": [], "late": [], "miss": 0, "polls": 0, "fail": 0, "conn": [],
                    "connect_all": math.nan, "rss_connected": math.nan, "rss_end": math.nan})
                op, v = row["op"], row["value"]
                if op == "poll_rtt" and n.get("status") == "0":
                    r["rtt"].append(float(v))
                elif op == "poll_resp":
                    r["polls"] += 1
                    r["miss"] += int(n.get("miss", "0"))
                    if n.get("status") != "0":
                        r["fail"] += 1
                    if v != "nan":
                        r["resp"].append(float(v))
                    r["late"].append(float(n.get("wake_late_us", "nan")))
                elif op == "connect":
                    r["conn"].append(float(v))
                elif op == "connect_all":
                    r["connect_all"] = float(v)
                elif op == "master_rss_kb":
                    stage = n.get("stage")
                    if stage == "all_connected":
                        r["rss_connected"] = float(v)
                    elif stage == "end":
                        r["rss_end"] = float(v)

    cols = ["run_id", "host", "cond", "kem", "sig", "period_ms", "session", "n", "mb_op", "polls",
            "rtt_mean_ms", "rtt_p50_ms", "rtt_p95_ms", "rtt_p99_ms", "rtt_max_ms",
            "cycle_p50_ms", "resp_p99_ms", "miss_pct", "fail", "wake_late_p50_us", "wake_late_p99_us",
            "connect_mean_ms", "connects", "connect_all_ms", "rss_connected_kb", "rss_end_kb"]
    out = []
    for r in runs.values():
        rtt, resp, late = sorted(r["rtt"]), sorted(r["resp"]), sorted(r["late"])
        out.append({
            **{k: r[k] for k in ("run_id", "host", "cond", "kem", "sig", "period_ms", "session", "n", "mb_op", "polls", "fail")},
            "cycle_p50_ms": pct(resp, 50), "connect_all_ms": r["connect_all"],
            "rss_connected_kb": r["rss_connected"], "rss_end_kb": r["rss_end"],
            "rtt_mean_ms": statistics.fmean(rtt) if rtt else math.nan,
            "rtt_p50_ms": pct(rtt, 50), "rtt_p95_ms": pct(rtt, 95), "rtt_p99_ms": pct(rtt, 99),
            "rtt_max_ms": rtt[-1] if rtt else math.nan, "resp_p99_ms": pct(resp, 99),
            "miss_pct": 100 * r["miss"] / r["polls"] if r["polls"] else math.nan,
            "wake_late_p50_us": pct(late, 50), "wake_late_p99_us": pct(late, 99),
            "connect_mean_ms": statistics.fmean(r["conn"]) if r["conn"] else math.nan, "connects": len(r["conn"]),
        })

    show = ["cond", "kem", "sig", "period_ms", "session", "n", "polls", "rtt_p50_ms", "rtt_p99_ms",
            "cycle_p50_ms", "resp_p99_ms", "miss_pct", "wake_late_p99_us", "connect_mean_ms", "connect_all_ms",
            "rss_end_kb", "host"]
    fmt = lambda v: f"{v:.4f}" if isinstance(v, float) else str(v)
    table = [[fmt(o[c]) for c in show] for o in out]
    widths = [max(len(c), *(len(t[i]) for t in table)) if table else len(c) for i, c in enumerate(show)]
    print("  ".join(c.ljust(w) for c, w in zip(show, widths)))
    for t in table:
        print("  ".join(v.ljust(w) for v, w in zip(t, widths)))

    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            for o in out:
                w.writerow({c: fmt(o[c]) for c in cols})
        print(f"\nwrote {a.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
