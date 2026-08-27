"""Diverse benign-traffic augmentation.

The real CIC-IDS2018 Infiltration day is a single environment: several benign
features (lateral_score, uniq_dst_ips, ttl_var, retrans_ratio) are effectively
constant there. A model trained on it alone treats *any* benign traffic with a
different shape — internal file shares, DNS-heavy hosts, backups — as an extreme
outlier and flags it as attack (false positive). This module synthesises several
distinct **benign** traffic profiles and runs them through the exact same feature
pipeline, so training sees a broad benign manifold and stops over-firing on
ordinary traffic it never saw during training. These windows are added to the
TRAIN split only — the test split stays pure real CIC-IDS2018, so the benchmark
remains an honest measurement on real data.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from pipeline.extract_features import build_windows

# each profile: (name, fn(rng)->one flow-row dict). Rows are benign by construction.
_INT = [f"10.0.0.{i}" for i in range(2, 60)]
_INT2 = [f"192.168.1.{i}" for i in range(2, 60)]
_EXT = ["203.0.113.5", "198.51.100.9", "8.8.8.8", "1.1.1.1", "104.18.2.10", "142.250.1.1"]


# realistic benign TCP window sizes seen across OSes/stacks (incl. the 65535 max),
# so the benign manifold covers the full range instead of one narrow value.
_WINS = [8192, 14600, 16384, 29200, 32768, 43690, 64240, 65535]


def _row(rng, src, dst, dport, nbytes, bwd, pkts, dur_us, iat_us, iat_sd, ttl, retrans):
    return {
        "src_ip": src, "dst_ip": dst, "dst_port": int(dport),
        "syn": 1, "ack": 1, "fin": rng.integers(0, 2), "rst": 0,
        "bytes": float(nbytes), "bwd_bytes": float(bwd), "packets": float(max(1, pkts)),
        "duration": float(dur_us), "iat_mean": float(iat_us), "iat_std": float(iat_sd),
        "ttl": int(ttl), "retrans": int(retrans),
        # packet-level fields vary across benign profiles too, so win_mean/frag_ratio/
        # payload_var don't read as anomalous for ordinary traffic.
        "win": int(rng.choice(_WINS)), "frag": int(rng.random() < 0.03),
        "label": "BENIGN",
    }


def _profiles(rng):
    """Yield one benign flow row from a randomly chosen realistic profile."""
    kind = rng.integers(0, 8)
    if kind == 6:  # internal clients -> internal app/web/ssh server (private->private,
        # few destinations, ports 443/80/22) — the most common intranet pattern and
        # exactly the shape that naive lateral_score over-flags.
        return _row(rng, rng.choice(_INT), rng.choice(_INT[:3]), rng.choice([443, 80, 22, 8080]),
                    rng.integers(500, 4000), rng.integers(500, 8000), rng.integers(5, 30),
                    rng.integers(50_000, 3_000_000), rng.integers(5_000, 200_000), rng.integers(1_000, 60_000),
                    rng.choice([64, 128]), rng.integers(0, 2))
    if kind == 7:  # internal clients -> internal server on 192.168 subnet, same shape
        return _row(rng, rng.choice(_INT2), rng.choice(_INT2[:3]), rng.choice([443, 80, 22]),
                    rng.integers(500, 4000), rng.integers(500, 8000), rng.integers(5, 30),
                    rng.integers(50_000, 3_000_000), rng.integers(5_000, 200_000), rng.integers(1_000, 60_000),
                    rng.choice([64, 128]), rng.integers(0, 2))
    if kind == 0:  # web browsing to external
        return _row(rng, rng.choice(_INT), rng.choice(_EXT), rng.choice([80, 443]),
                    rng.integers(600, 4000), rng.integers(2000, 40000), rng.integers(6, 40),
                    rng.integers(50_000, 3_000_000), rng.integers(10_000, 400_000), rng.integers(2_000, 80_000),
                    rng.choice([54, 56, 60, 64, 128]), rng.integers(0, 2))
    if kind == 1:  # internal file share (private->private, single dst — NOT fan-out)
        return _row(rng, rng.choice(_INT), rng.choice(_INT[:6]), rng.choice([445, 139, 2049]),
                    rng.integers(2000, 60000), rng.integers(1000, 20000), rng.integers(10, 120),
                    rng.integers(100_000, 5_000_000), rng.integers(5_000, 200_000), rng.integers(1_000, 50_000),
                    rng.choice([64, 128]), rng.integers(0, 3))
    if kind == 2:  # DNS: tiny, port 53, short
        return _row(rng, rng.choice(_INT2), rng.choice(_INT2[:3] + ["8.8.8.8"]), 53,
                    rng.integers(80, 400), rng.integers(80, 600), rng.integers(2, 6),
                    rng.integers(1_000, 100_000), rng.integers(500, 20_000), rng.integers(100, 8_000),
                    rng.choice([64, 128, 255]), 0)
    if kind == 3:  # bulk backup: large bytes, high out-ratio
        return _row(rng, rng.choice(_INT), rng.choice(_INT[:4]), rng.choice([873, 22, 9000]),
                    rng.integers(50000, 500000), rng.integers(500, 5000), rng.integers(50, 400),
                    rng.integers(1_000_000, 20_000_000), rng.integers(2_000, 100_000), rng.integers(1_000, 40_000),
                    rng.choice([64, 128]), rng.integers(0, 5))
    if kind == 4:  # database calls, internal, steady
        return _row(rng, rng.choice(_INT2), rng.choice(_INT2[:5]), rng.choice([3306, 5432, 1433]),
                    rng.integers(400, 8000), rng.integers(400, 12000), rng.integers(5, 60),
                    rng.integers(20_000, 2_000_000), rng.integers(2_000, 150_000), rng.integers(500, 40_000),
                    rng.choice([64, 128]), rng.integers(0, 2))
    # kind == 5: SSH admin session, external->internal, long-lived
    return _row(rng, rng.choice(_EXT), rng.choice(_INT), 22,
                rng.integers(1000, 30000), rng.integers(1000, 30000), rng.integers(20, 200),
                rng.integers(2_000_000, 30_000_000), rng.integers(50_000, 2_000_000), rng.integers(10_000, 500_000),
                rng.choice([54, 60, 64]), rng.integers(0, 4))


def benign_windows(n_windows: int, window_ms: int, stride_ms: int, seed: int = 123):
    """Return (feat (M,D), stage_idx (M,)) of diverse benign windows. Generates a
    contiguous benign timeline (~n_windows windows) via the real feature pipeline."""
    rng = np.random.default_rng(seed)
    flows_per_window = 30
    n_flows = n_windows * flows_per_window
    t0 = 1_600_000_000_000  # fixed historical epoch-ms base (deterministic)
    rows = []
    for i in range(n_flows):
        r = _profiles(rng)
        # spread flows uniformly across the requested number of windows
        r["ts"] = float(t0 + int(i / flows_per_window) * stride_ms + rng.integers(0, window_ms))
        rows.append(r)
    df = pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)
    feat, stage_idx, _ = build_windows(df, window_ms, stride_ms)
    return feat, np.zeros(len(feat), dtype=int)
