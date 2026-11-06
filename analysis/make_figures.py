#!/usr/bin/env python3
"""Meeting 2 figures from results/summary/*.csv -> analysis/figures/*.png
Usage: python3 analysis/make_figures.py [--host JOSPC-wsl2]"""
import argparse, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="JOSPC-wsl2")
a = ap.parse_args()
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = "analysis/figures"
os.makedirs(OUT, exist_ok=True)

# Reference palette (dataviz skill, light mode): categorical slots 1-3 + text/surface tokens
SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
C1, C2, C3 = "#2a78d6", "#eb6834", "#1baf7a"
C2_RAMP = ["#f6b08e", "#eb6834", "#a8401a"]   # Dilithium2/3/5: one hue, light -> dark
GENERIC = "#b9b8b2"

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.8, "axes.axisbelow": True, "legend.frameon": False,
})


def rows(path, **filt):
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(f) if all(r.get(k) == v for k, v in filt.items())]


def save(fig, name):
    p = f"{OUT}/{name}.png"
    fig.savefig(p, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", p)


def lvl(s):
    return s.replace("dilithium", "D").replace("kyber", "K").replace("ecdsa-p256", "ECDSA")


# ---- Fig 1: handshake latency, fair (SP) build ----
hs = rows("results/summary/table8_HS30_connect.csv", host=a.host)
labels, p50, p95, col = [], [], [], []
for r in hs:
    labels.append(f"{r['condition']}  {r['kem']} + {r['sig']}")
    p50.append(float(r["p50"])); p95.append(float(r["p95"]))
    col.append({"C1": C1, "C2": C2, "C3": C3}[r["condition"]])
fig, ax = plt.subplots(figsize=(8, 5.6))
y = list(range(len(labels)))[::-1]
ax.barh(y, p50, color=col, height=0.62, edgecolor=SURF, linewidth=2)
for yi, a50, a95 in zip(y, p50, p95):
    ax.plot([a50, a95], [yi, yi], color=INK2, linewidth=1.2)
    ax.plot([a95], [yi], marker="|", color=INK2, markersize=7)
    ax.text(a95 + 0.04, yi, f"{a50:.2f}", va="center", fontsize=9, color=INK)
ax.set_yticks(y, labels, fontsize=9)
ax.set_xlabel("handshake time, ms (bar = median, whisker = p95)")
ax.set_title("Handshake latency on a fair build (loopback, 30 runs × 100 handshakes)", loc="left")
ax.grid(axis="y", visible=False)
ax.set_xlim(0, max(p95) * 1.15)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=C1, label="C1 classical"), Patch(color=C2, label="C2 post-quantum"),
                   Patch(color=C3, label="C3 hybrid")], loc="upper right")
save(fig, "fig1_handshake_latency")

# ---- Fig 2: build fairness, generic vs optimized ECC ----
gen = {(r["kem"], r["sig"]): float(r["p50"]) for r in rows("results/summary/table8_HS30GEN_connect.csv", host=a.host)}
opt = {(r["kem"], r["sig"]): float(r["p50"]) for r in hs}
pairs = [("p256", "ecdsa-p256", "C1  P-256 + ECDSA"), ("x25519", "ecdsa-p256", "C1  X25519 + ECDSA"),
         ("kyber768", "dilithium3", "C2  Kyber768 + Dilithium3")]
fig, ax = plt.subplots(figsize=(7.2, 3.8))
w = 0.36
for i, (k, s, lab) in enumerate(pairs):
    c = C1 if lab.startswith("C1") else C2
    for dx, v, colr in ((-w / 2, gen[(k, s)], GENERIC), (w / 2, opt[(k, s)], c)):
        ax.bar(i + dx, v, w, color=colr, edgecolor=SURF, linewidth=2)
        ax.text(i + dx, v + 0.05, f"{v:.2f}", ha="center", fontsize=9)
ax.set_xticks(range(len(pairs)), [p[2] for p in pairs], fontsize=9)
ax.set_ylabel("median handshake, ms")
ax.set_title("Same algorithms, different build: generic vs optimized ECC math", loc="left")
ax.grid(axis="x", visible=False)
ax.legend(handles=[Patch(color=GENERIC, label="generic ECC math (first build)"),
                   Patch(color=C1, label="optimized build: classical"),
                   Patch(color=C2, label="optimized build: post-quantum")], loc="upper right")
save(fig, "fig2_build_fairness")

# ---- Fig 3: bytes on the wire ----
b = rows("results/summary/table9_bytes_wire.csv")
fig, ax = plt.subplots(figsize=(7.6, 4))
xs, xl = [], []
x = 0
for r in [r for r in b if r["condition"] == "C1"]:
    v = int(r["total_bytes"]) / 1000
    ax.bar(x, v, 0.7, color=C1, edgecolor=SURF, linewidth=2); ax.text(x, v + 0.4, f"{v:.1f}", ha="center", fontsize=8)
    xs.append(x); xl.append(r["kem"].replace("secp256r1", "P-256").replace("x25519", "X25519")); x += 1
x += 0.6
for di, d in enumerate(["dilithium2", "dilithium3", "dilithium5"]):
    for r in [r for r in b if r["sig"] == d]:
        v = int(r["total_bytes"]) / 1000
        ax.bar(x, v, 0.7, color=C2_RAMP[di], edgecolor=SURF, linewidth=2)
        ax.text(x, v + 0.4, f"{v:.1f}", ha="center", fontsize=8)
        xs.append(x); xl.append(f"{lvl(r['kem'])}\n{lvl(d)}"); x += 1
    x += 0.6
ax.set_xticks(xs, xl, fontsize=8)
ax.set_ylabel("KB per connection (both directions)")
ax.set_title("Bytes on the wire per handshake: post-quantum sends 8–15× more", loc="left")
ax.grid(axis="x", visible=False)
ax.legend(handles=[Patch(color=C1, label="C1 classical (ECDSA-P256 certs)")] +
          [Patch(color=c, label=f"C2 Dilithium{n}") for c, n in zip(C2_RAMP, (2, 3, 5))], loc="upper left")
save(fig, "fig3_bytes_on_wire")

# ---- Fig 4: emulated links, time to first Modbus response ----
lk = rows("results/summary/table8_LINK_ttfr.csv", host=a.host)
links = [("wan", "WAN / VPN\n50 ms RTT, 10 Mbps"), ("cell", "Cellular modem\n80 ms RTT, 2 Mbps"),
         ("serial115k", "Serial / radio bridge\n115.2 kbps")]
series = [("C1", "x25519", "ecdsa-p256", "C1 X25519 + ECDSA", C1),
          ("C2", "kyber512", "dilithium2", "C2 Kyber512 + Dilithium2", C2_RAMP[0]),
          ("C2", "kyber768", "dilithium3", "C2 Kyber768 + Dilithium3", C2_RAMP[1]),
          ("C2", "kyber1024", "dilithium5", "C2 Kyber1024 + Dilithium5", C2_RAMP[2])]
fig, axs = plt.subplots(1, 3, figsize=(10, 3.8))
for ax, (ln, title) in zip(axs, links):
    vals = []
    for i, (c, k, s, lab, colr) in enumerate(series):
        v = next(float(r["p50"]) for r in lk if r["link"] == ln and r["condition"] == c and r["kem"] == k and r["sig"] == s)
        vals.append(v)
        ax.bar(i, v, 0.72, color=colr, edgecolor=SURF, linewidth=2)
        txt = f"{v:.0f}" if i == 0 else f"{v:.0f}\n{v / vals[0]:.1f}×"
        ax.text(i, v * 1.02, txt, ha="center", va="bottom", fontsize=8, linespacing=1.1)
    ax.set_title(title, fontsize=10, loc="left")
    ax.set_xticks([]); ax.grid(axis="x", visible=False)
    ax.set_ylim(0, max(vals) * 1.25)
axs[0].set_ylabel("time to first Modbus response, ms")
fig.legend(handles=[Patch(color=s[4], label=s[3]) for s in series], loc="lower center", ncol=4, fontsize=8.5,
           bbox_to_anchor=(0.5, -0.06))
fig.suptitle("Time to first Modbus response with a new session per poll, emulated links (median of 20; × = vs classical)", x=0.01, ha="left",
             fontweight="bold", fontsize=12)
fig.tight_layout()
save(fig, "fig4_links_ttfr")
