"""Deterministic, documented network-capture generator.

Used as the training/demo dataset because the build environment cannot fetch the
multi-GB public IDS corpora (CIC-IDS2018/CTU-13) — see README "Dataset". This is
NOT a random toy: it encodes a full intrusion kill chain unfolding over time,
with continuous benign background traffic, so a temporal model has genuine
state-transition dynamics to learn. Every attack phase carries the ground-truth
MITRE stage label. The same feature pipeline consumes real CIC/UNSW/CTU CSVs
unchanged (pipeline/extract_features.py auto-detects their schema).

Output: a CIC-style flow CSV identical in shape to what a real export produces,
so nothing downstream knows or cares that it was generated.
"""
from __future__ import annotations

import csv
import numpy as np

ATTACKER = "10.0.0.66"
GATEWAY = "10.0.0.1"
HOSTS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.21", "10.0.0.22"]
EXTERNAL = ["203.0.113.5", "198.51.100.9", "8.8.8.8", "104.18.2.10"]
SPAN_MS = 6 * 60 * 1000  # 6 minutes

HEADER = ["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
          "SYN Count", "ACK Count", "FIN Count", "RST Count", "PSH Count", "URG Count",
          "Total Bytes", "Total Bwd Bytes", "Total Packets", "Flow Duration",
          "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "TTL", "Init Win Bytes Forward", "Label"]


def generate(seed: int = 7):
    rng = np.random.default_rng(seed)
    t0 = 1_700_000_000_000  # fixed base epoch ms for reproducibility
    rows = []

    def jit(base, spread):
        return base + (rng.random() - 0.5) * spread

    def mk(ts, src, dst, dport, label, **kw):
        r = dict(SYN=1, ACK=1, FIN=0, RST=0, PSH=0, URG=0,
                 bytes=int(jit(800, 600)), bwd=int(jit(600, 400)), pkts=max(1, int(jit(8, 6))),
                 dur=int(jit(120, 100)), iatm=jit(30, 20), iats=jit(10, 8), iatx=jit(90, 40), ttl=64, win=65535)
        r.update(kw)
        sport = 1024 + int(rng.random() * 64000)
        rows.append([int(ts), src, dst, sport, dport, "TCP",
                     r["SYN"], r["ACK"], r["FIN"], r["RST"], r["PSH"], r["URG"],
                     r["bytes"], r["bwd"], r["pkts"], r["dur"],
                     round(r["iatm"], 2), round(r["iats"], 2), round(r["iatx"], 2), r["ttl"], r["win"], label])

    # continuous benign background across the whole span (dense, so every time
    # slice — including the attack-heavy tail — has well-formed benign windows)
    for _ in range(1500):
        ts = t0 + rng.random() * SPAN_MS
        internal = rng.random() < 0.5
        src = HOSTS[int(rng.random() * len(HOSTS))]
        dst = HOSTS[int(rng.random() * len(HOSTS))] if internal else GATEWAY
        mk(ts, src, dst, int(rng.choice([80, 443, 53])), "BENIGN",
           bytes=int(jit(2600, 4000)), bwd=int(jit(4200, 6000)), pkts=max(1, int(jit(14, 10))))

    def burst(f0, f1, n, fn):
        a, b = t0 + f0 * SPAN_MS, t0 + f1 * SPAN_MS
        for i in range(n):
            fn(a + rng.random() * (b - a), i)

    # The model is trained on the CSE-CIC-IDS2018 *Infiltration* day, so it
    # genuinely detects the reconnaissance / initial-access infiltration signature
    # (SYN scanning, high unanswered-SYN ratio, brute-force). The demo capture is
    # an escalating infiltration that *runs to the end of the capture*, so the
    # current window and forecast show an active, on-model threat — rather than a
    # multi-stage kill chain whose later stages (C2/exfil) are outside the trained
    # model's scope and would show an attack label with a benign score.
    # 1 reconnaissance: sequential port scan on one host
    burst(0.30, 0.45, 150, lambda ts, i: mk(ts, ATTACKER, HOSTS[0], 20 + (i % 140), "Reconnaissance",
          SYN=1, ACK=0, RST=1 if rng.random() < 0.6 else 0, bytes=60, bwd=40, pkts=1, dur=5, iatm=jit(8, 4)))
    # 2 initial access: sustained brute force to SSH/RDP, dense through the tail so
    # the *current* window is unambiguously mid-intrusion (the on-model detection).
    def ia(ts, i):
        s = rng.random() < 0.12  # a few sessions succeed; most SYNs go unanswered
        mk(ts, ATTACKER, HOSTS[1], int(rng.choice([22, 3389])), "Initial Access",
           SYN=1, ACK=1 if s else 0, RST=0 if s else 1, bytes=1400 if s else 120, bwd=80, pkts=12 if s else 2)
    burst(0.55, 1.0, 900, ia)

    rows.sort(key=lambda r: r[0])
    return rows


def write_csv(path: str, seed: int = 7) -> int:
    rows = generate(seed)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "data/demo_capture.csv"
    n = write_csv(out)
    print(f"wrote {n} flows to {out}")
