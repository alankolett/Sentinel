"""Feature & state-representation pipeline.

Ingests a NetFlow/IPFIX-style flow CSV (CIC-IDS / UNSW-NB15 / CTU-13 / generic or
the bundled synthetic capture), auto-detects the schema, and produces a
timestamped, windowed feature matrix — the network-state sequence S_1..S_N that
the world model operates on. Ground-truth attack-stage labels per window are
derived from the dataset annotations via config/mitre_mapping.yaml.

Feature vector per 5 s window (flow-level; packet-level fields TTL/window/retrans
are used when present, else 0):
  flow_count, uniq_dst_ports, uniq_dst_ips, syn_ratio, syn_ack_ratio, rst_ratio,
  fin_ratio, avg_bytes, avg_pkts, avg_dur, iat_mean, iat_var, port_scan_score,
  failed_conn_ratio, lateral_score, bytes_out_ratio, ttl_var, retrans_ratio
"""
from __future__ import annotations

import os
import re
import numpy as np
import pandas as pd
import yaml

FEATURES = [
    "flow_count", "uniq_dst_ports", "uniq_dst_ips", "syn_ratio", "syn_ack_ratio",
    "rst_ratio", "fin_ratio", "avg_bytes", "avg_pkts", "avg_dur", "iat_mean",
    "iat_var", "port_scan_score", "failed_conn_ratio", "lateral_score",
    "bytes_out_ratio", "ttl_var", "retrans_ratio",
    # packet-level (PS-required): TCP window size, IP fragment flags, payload size
    # distribution. Sourced from PCAP or from CIC-style columns when present.
    "win_mean", "frag_ratio", "payload_var",
]

_CFG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")

# internal field -> accepted header synonyms (normalised)
SYNONYMS = {
    "ts": ["timestamp", "time", "stime", "flowstarttime", "ts", "starttime"],
    "src_ip": ["srcip", "sourceip", "sa", "sourceipaddress", "ipsrc", "idorigh"],
    "dst_ip": ["dstip", "destinationip", "da", "destinationipaddress", "ipdst", "idresph"],
    "src_port": ["srcport", "sport", "sourceport", "l4srcport", "idorigp"],
    "dst_port": ["dstport", "dport", "destinationport", "l4dstport", "idrespp"],
    "protocol": ["protocol", "proto", "protocolname"],
    "bytes": ["bytes", "totbytes", "totalbytes", "sbytes", "totalfwdbytes", "totlenfwdpackets", "totlenfwdpkts", "origbytes"],
    "bwd_bytes": ["dbytes", "totalbwdbytes", "totlenbwdpackets", "totlenbwdpkts", "respbytes"],
    "packets": ["packets", "totpkts", "totalpackets", "spkts", "totalfwdpackets", "totfwdpkts"],
    "duration": ["duration", "flowduration", "dur"],
    "syn": ["syncount", "syn", "synflagcount", "synflagcnt"],
    "ack": ["ackcount", "ack", "ackflagcount", "ackflagcnt"],
    "fin": ["fincount", "fin", "finflagcount", "finflagcnt"],
    "rst": ["rstcount", "rst", "rstflagcount", "rstflagcnt"],
    "psh": ["pshcount", "psh", "pshflagcount", "pshflagcnt", "fwdpshflags"],
    "urg": ["urgcount", "urg", "urgflagcount", "urgflagcnt", "fwdurgflags"],
    "iat_mean": ["flowiatmean", "iatmean"],
    "iat_std": ["flowiatstd", "iatstd", "flowiatvar"],
    "ttl": ["ttl", "sttl", "meanttl"],
    "win": ["initwinbytesforward", "initfwdwinbyts", "windowsize", "tcpwindow", "swin"],
    "retrans": ["retrans", "retransmissions"],
    "frag": ["frag", "ipflags", "fragflag", "fragments", "fragoffset", "ipfragflag"],
    "label": ["label", "attackcat", "attackcategory", "class", "category", "detailedlabel"],
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).strip().lower())


def load_mapping(path: str | None = None):
    path = path or os.path.join(_CFG_DIR, "mitre_mapping.yaml")
    with open(path) as f:
        cfg = yaml.safe_load(f)
    stages = sorted(cfg["stages"], key=lambda s: s["order"])
    stage_names = [s["name"] for s in stages]
    technique = {s["name"]: s["technique"] for s in stages}
    # longest label patterns first so specific matches win
    label_map = sorted(cfg["label_map"].items(), key=lambda kv: -len(kv[0]))
    return stage_names, technique, label_map


def label_to_stage(raw: str, label_map) -> str:
    if raw is None or (isinstance(raw, float) and np.isnan(raw)):
        return "benign"
    s = str(raw).strip().lower()
    if s in ("", "-", "0", "benign", "normal", "background"):
        return "benign"
    for pat, stage in label_map:
        if pat in s:
            return stage
    return "benign"


def detect_schema(header):
    normed = [_norm(h) for h in header]
    mapping, matched = {}, 0
    for field, syns in SYNONYMS.items():
        idx = next((i for i, h in enumerate(normed) if h in syns), -1)
        mapping[field] = idx
        if idx >= 0:
            matched += 1
    ds = "generic flow CSV"
    sset = set(normed)
    if "attackcat" in sset or "sttl" in sset:
        ds = "UNSW-NB15"
    elif "idorigh" in sset or "connstate" in sset or "detailedlabel" in sset:
        ds = "CTU-13 / Zeek"
    elif any("flowiat" in h for h in normed):
        ds = "CIC-IDS / CICIoT"
    return mapping, matched, ds


def parse_flows(path: str) -> tuple[pd.DataFrame, dict]:
    df_raw = pd.read_csv(path, low_memory=False)
    mapping, matched, dataset = detect_schema(list(df_raw.columns))
    if matched < 3:
        raise ValueError(f"Unrecognised schema: only {matched} known columns matched.")

    def col(field, default=0.0):
        idx = mapping.get(field, -1)
        if idx < 0:
            return pd.Series(default, index=df_raw.index)
        return df_raw.iloc[:, idx]

    def num(field, default=0.0):
        return pd.to_numeric(col(field, default), errors="coerce").fillna(default)

    n = len(df_raw)
    raw_ts = col("ts", np.nan)
    ts = pd.to_numeric(raw_ts, errors="coerce")
    if ts.isna().all():
        # not epoch numbers — try wall-clock datetime strings (CIC-IDS2018 style),
        # else fall back to synthetic 1-per-second ordering.
        dt = pd.to_datetime(raw_ts, errors="coerce")
        if dt.notna().any():
            # force millisecond resolution so the int64 epoch is unambiguous
            ms = dt.values.astype("datetime64[ms]").astype("int64").astype(float)
            ts = pd.Series(ms, index=dt.index).where(dt.notna(), np.nan)
        else:
            ts = pd.Series(np.arange(n, dtype=float) * 1000.0)
    else:
        m = ts.median()
        if m > 1e15:
            ts = ts / 1000.0
        elif m < 1e9:  # relative seconds
            ts = ts * 1000.0
        ts = ts.ffill().fillna(0)

    df = pd.DataFrame({
        "ts": ts.astype(float),
        "src_ip": col("src_ip", "0.0.0.0").astype(str),
        "dst_ip": col("dst_ip", "0.0.0.0").astype(str),
        "dst_port": num("dst_port").astype(int),
        "syn": num("syn"), "ack": num("ack"), "fin": num("fin"), "rst": num("rst"),
        "bytes": num("bytes"), "bwd_bytes": num("bwd_bytes"),
        "packets": num("packets", 1.0).clip(lower=1),
        "duration": num("duration"),
        "iat_mean": num("iat_mean"), "iat_std": num("iat_std"),
        "ttl": num("ttl"), "retrans": num("retrans"),
        "win": num("win"), "frag": num("frag"),
        "label": col("label", "").astype(str),
    })
    df = df[np.isfinite(df.ts)]                       # drop repeated-header / junk rows
    df = df[df.label.str.lower() != "label"]
    df = df.sort_values("ts").reset_index(drop=True)
    if len(df) == 0:
        raise ValueError("No parseable flow rows after cleaning.")
    return df, {"dataset": dataset, "matched": matched, "rows": len(df), "mapping": mapping}


def _is_private(ip: str) -> bool:
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.0\.0\.1)", ip))


def _port_scan_score(ports: np.ndarray) -> float:
    u = np.unique(ports)
    if len(u) < 4:
        return 0.0
    u.sort()
    steps = int(np.sum(np.diff(u) <= 3))
    seq = steps / (len(u) - 1)
    breadth = min(1.0, len(u) / 50.0)
    return float(max(seq, breadth))


def _window_vector(w: pd.DataFrame) -> np.ndarray:
    n = len(w)
    syn, ack, fin, rst = w.syn.sum(), w.ack.sum(), w.fin.sum(), w.rst.sum()
    pkts = w.packets.sum()
    ports = w.dst_port.to_numpy()
    uniq_ports = len(np.unique(ports))
    lateral = np.mean([_is_private(s) and _is_private(d) for s, d in zip(w.src_ip, w.dst_ip)]) if n else 0.0
    b_out, b_in = w.bytes.sum(), w.bwd_bytes.sum()
    # packet-level: mean TCP window size, IP-fragment-flag ratio, and payload-size
    # distribution spread (std of per-flow mean payload = bytes/packets) per window.
    win = w.win if "win" in w else pd.Series(dtype=float)
    frag = w.frag if "frag" in w else pd.Series(dtype=float)
    win_mean = float(win[win > 0].mean()) if (len(win) and (win > 0).any()) else 0.0
    frag_ratio = float((frag > 0).mean()) if len(frag) else 0.0
    per_flow_payload = (w.bytes / w.packets.clip(lower=1)) if n else pd.Series(dtype=float)
    payload_var = float(per_flow_payload.std()) if n > 1 else 0.0
    vec = {
        "flow_count": n,
        "uniq_dst_ports": uniq_ports,
        "uniq_dst_ips": w.dst_ip.nunique(),
        "syn_ratio": syn / max(pkts, 1),
        "syn_ack_ratio": syn / max(ack, 1),
        "rst_ratio": rst / max(pkts, 1),
        "fin_ratio": fin / max(pkts, 1),
        "avg_bytes": w.bytes.mean(),
        "avg_pkts": w.packets.mean(),
        "avg_dur": w.duration.mean(),
        "iat_mean": w.iat_mean.mean(),
        "iat_var": w.iat_std.mean(),
        "port_scan_score": _port_scan_score(ports),
        "failed_conn_ratio": max(0.0, (syn - ack) / max(syn, 1)),
        "lateral_score": lateral,
        "bytes_out_ratio": b_out / max(b_out + b_in, 1),
        "ttl_var": w.ttl.std() if n > 1 else 0.0,
        "retrans_ratio": w.retrans.sum() / max(pkts, 1),
        "win_mean": win_mean,
        "frag_ratio": frag_ratio,
        "payload_var": payload_var,
    }
    return np.array([vec[f] if np.isfinite(vec[f]) else 0.0 for f in FEATURES], dtype=float)


def build_windows(df: pd.DataFrame, window_ms=5000, stride_ms=5000, label_map=None):
    """Return (feat matrix (N,D), stage_idx (N,), meta list). Stage index uses the
    canonical order from the mapping (0 = benign)."""
    stage_names, _, lm = load_mapping()
    label_map = label_map or lm
    stage_to_idx = {s: i for i, s in enumerate(stage_names)}
    t0, tN = df.ts.iloc[0], df.ts.iloc[-1]
    span = max(1.0, tN - t0)
    feats, stages, meta = [], [], []
    use_time = span > window_ms * 2
    if use_time and window_ms == stride_ms:
        # fast path: bucket flows by fixed window id (O(n)), not per-window scan.
        bucket = ((df.ts - t0) // window_ms).astype(np.int64)
        for bid, w in df.groupby(bucket, sort=True):
            start = t0 + int(bid) * window_ms
            feats.append(_window_vector(w))
            stages.append(_window_stage(w, label_map, stage_to_idx))
            meta.append({"t_start": float(start), "t_end": float(start + window_ms), "flows": int(len(w))})
        return np.array(feats), np.array(stages, dtype=int), meta
    if use_time:
        starts = np.arange(t0, tN + 1, stride_ms)
        for start in starts:
            w = df[(df.ts >= start) & (df.ts < start + window_ms)]
            if len(w) == 0:
                continue
            feats.append(_window_vector(w))
            sev = _window_stage(w, label_map, stage_to_idx)
            stages.append(sev)
            meta.append({"t_start": float(start), "t_end": float(start + window_ms), "flows": int(len(w))})
    else:
        per = max(5, len(df) // max(6, min(40, len(df) // 20 or 6)))
        idxs = list(range(0, len(df), per))
        for i in idxs:
            w = df.iloc[i:i + per]
            if len(w) == 0:
                continue
            feats.append(_window_vector(w))
            stages.append(_window_stage(w, label_map, stage_to_idx))
            meta.append({"t_start": float(w.ts.iloc[0]), "t_end": float(w.ts.iloc[-1]), "flows": int(len(w))})
    return np.array(feats), np.array(stages, dtype=int), meta


def _window_stage(w, label_map, stage_to_idx):
    """Most-severe (highest-order) attack stage present in the window."""
    best = 0
    for raw in w.label:
        idx = stage_to_idx.get(label_to_stage(raw, label_map), 0)
        best = max(best, idx)
    return best


def make_sequences(feat: np.ndarray, stage_idx: np.ndarray, seqlen: int):
    """Build supervised next-state samples: window t-seqlen+1..t -> (S_{t+1},
    stage_{t+1}). Learns P(S_{t+1} | history)."""
    X, y_next, y_stage, anchor = [], [], [], []
    N = len(feat)
    for t in range(seqlen - 1, N - 1):
        X.append(feat[t - seqlen + 1:t + 1])
        y_next.append(feat[t + 1])
        y_stage.append(stage_idx[t + 1])
        anchor.append(t + 1)
    if not X:
        raise ValueError("Capture too short for the configured sequence length.")
    return np.array(X), np.array(y_next), np.array(y_stage, dtype=int), np.array(anchor)
