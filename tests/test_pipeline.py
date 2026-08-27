"""Sentinel test suite. Run: pytest -q"""
import json
import os

import numpy as np
import pandas as pd
import pytest

from pipeline.extract_features import (
    detect_schema, _window_vector, build_windows, make_sequences, FEATURES,
    label_to_stage, load_mapping,
)
from pipeline.synth import generate, write_csv, HEADER
from pipeline.evaluate import load_config, prepare, train_models, evaluate
from models.world_model import LSTMWorldModel, _softmax
from backend.infer import analyze_csv, benchmark

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------- feature pipeline: known input -> known output ----------------

def test_schema_detection_cic_style():
    mapping, matched, ds = detect_schema(["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port",
                                           "Protocol", "SYN Count", "Flow IAT Mean", "Label"])
    assert matched >= 7
    assert mapping["src_ip"] >= 0 and mapping["dst_port"] >= 0
    assert ds == "CIC-IDS / CICIoT"


def test_label_mapping():
    _, _, lm = load_mapping()
    assert label_to_stage("BENIGN", lm) == "benign"
    assert label_to_stage("PortScan", lm) == "reconnaissance"
    assert label_to_stage("Exfiltration", lm) == "exfiltration"
    assert label_to_stage("SSH-Patator", lm) == "initial_access"
    assert label_to_stage(None, lm) == "benign"


def test_window_vector_known_values():
    # 4 flows, 2 distinct dst ports, 2 unanswered SYNs -> deterministic features
    df = pd.DataFrame({
        "src_ip": ["10.0.0.1"] * 4, "dst_ip": ["10.0.0.2"] * 4,
        "dst_port": [80, 80, 443, 22], "syn": [1, 1, 1, 1], "ack": [1, 1, 0, 0],
        "fin": [0, 0, 0, 0], "rst": [0, 0, 0, 0], "bytes": [100, 100, 100, 100],
        "bwd_bytes": [100, 100, 100, 100], "packets": [1, 1, 1, 1], "duration": [10, 10, 10, 10],
        "iat_mean": [5, 5, 5, 5], "iat_std": [1, 1, 1, 1], "ttl": [64, 64, 64, 64], "retrans": [0, 0, 0, 0],
    })
    v = _window_vector(df)
    f = dict(zip(FEATURES, v))
    assert f["flow_count"] == 4
    assert f["uniq_dst_ports"] == 3
    assert f["uniq_dst_ips"] == 1
    assert abs(f["failed_conn_ratio"] - 0.5) < 1e-9   # 2 of 4 SYNs unanswered
    assert abs(f["bytes_out_ratio"] - 0.5) < 1e-9
    assert np.all(np.isfinite(v))


# ---------------- synthetic dataset ----------------

def test_synth_is_deterministic_and_labelled():
    a = generate(7)
    b = generate(7)
    assert a == b                                   # reproducible
    labels = {r[-1] for r in a}
    # demo capture is an on-model infiltration (recon -> brute-force initial access)
    # over benign background; later kill-chain stages are outside the CIC-IDS2018
    # (infiltration-day) trained scope and were removed to avoid label/score mismatch.
    assert "Initial Access" in labels and "Reconnaissance" in labels and "BENIGN" in labels


# ---------------- world model: real gradients ----------------

def test_lstm_gradients_numerically_correct():
    rng = np.random.default_rng(0)
    D, H, C, T, B = 4, 5, 3, 3, 2
    m = LSTMWorldModel(D, H, C, seed=1)
    m.x_mean = np.zeros(D); m.x_std = np.ones(D)
    X = rng.normal(size=(B, T, D)); yn = rng.normal(size=(B, D)); ys = rng.integers(0, C, size=B)

    def loss():
        ns, st, _ = m._forward(X)
        p = _softmax(st)
        return 0.5 * np.mean((ns - yn) ** 2) - np.mean(np.log(p[np.arange(B), ys] + 1e-9))

    ns, st, cache = m._forward(X)
    g = m._backward(X, cache, ns, st, yn, ys, 1.0)
    eps, maxrel = 1e-5, 0.0
    for k in ["Wx", "Wh", "b", "Wns", "bns", "Wst", "bst"]:
        P, gk = m.params[k], g[k]
        for c, idx in enumerate(np.ndindex(P.shape)):
            if c >= 6:
                break
            old = P[idx]; P[idx] = old + eps; lp = loss(); P[idx] = old - eps; lm = loss(); P[idx] = old
            num = (lp - lm) / (2 * eps)
            maxrel = max(maxrel, abs(num - gk[idx]) / (abs(num) + abs(gk[idx]) + 1e-9))
    assert maxrel < 1e-4, f"gradient error {maxrel}"


def test_lstm_overfits_tiny_batch():
    rng = np.random.default_rng(2)
    X = rng.normal(size=(50, 3, 4)); yn = rng.normal(size=(50, 4)); ys = rng.integers(0, 3, size=50)
    m = LSTMWorldModel(4, 8, 3, seed=3)
    h = m.fit(X, yn, ys, epochs=200, lr=1e-2, batch=16)
    assert h[-1] < h[0] * 0.6


def test_rollout_and_attribution_shapes():
    rng = np.random.default_rng(4)
    X = rng.normal(size=(60, 3, 4)); yn = rng.normal(size=(60, 4)); ys = rng.integers(0, 3, size=60)
    m = LSTMWorldModel(4, 8, 3, seed=5); m.fit(X, yn, ys, epochs=50, lr=1e-2)
    m.calibrate(X, yn, X[:, -1, :])
    roll = m.rollout(X[0], k=5)
    assert len(roll) == 5 and all(0 <= s["infiltration"] <= 1 for s in roll)
    fc, tc = m.attribute(X[0][None])
    assert fc.shape == (4,) and tc.shape == (3,)


# ---------------- integration ----------------

def test_end_to_end_analyze_wellformed():
    path = os.path.join(ROOT, "data", "demo_capture.csv")
    if not os.path.exists(path):
        write_csv(path)
    r = analyze_csv(path)
    for key in ["currentStage", "predictedStage", "currentInfiltration", "forecast",
                "attributions", "topHosts", "graph", "threatLevel", "meta"]:
        assert key in r
    assert len(r["forecast"]) == 6
    assert len(r["attributions"]) == len(FEATURES)
    assert 0.0 <= r["currentInfiltration"] <= 1.0
    assert r["graph"]["nodes"] and r["topHosts"]


def test_benchmark_reproducible_matches_saved():
    """The numbers served by the API must equal a fresh evaluation — else the UI
    would be showing stale/invented figures."""
    saved = benchmark()
    cfg = load_config()
    data = prepare(cfg)
    world, base = train_models(cfg, data)
    fresh = evaluate(cfg, data, world, base)
    assert abs(fresh["world"]["f1"] - saved["world"]["f1"]) < 1e-9
    assert abs(fresh["baseline"]["f1"] - saved["baseline"]["f1"]) < 1e-9
    assert fresh["world"]["f1"] > fresh["baseline"]["f1"]      # world model wins


def _benign_csv(path, n=400, seed=1):
    """An ordinary all-benign capture: a few internal hosts to one server on
    443/80/22, moderate byte counts — the shape that used to trip a ~0.98
    infiltration false positive before robust standardization."""
    rng = np.random.default_rng(seed)
    srcs = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
    rows = []
    for i in range(n):
        b = int(rng.integers(800, 1300))
        rows.append([1_700_000_000_000 + i * 300, srcs[i % 4], "10.0.0.100",
                     int(rng.integers(30000, 60000)), [443, 80, 22][i % 3], "TCP",
                     1, 1, 0, 0, 0, 0, b, b // 2, int(rng.integers(6, 14)),
                     int(rng.integers(80, 200)), round(float(rng.uniform(20, 45)), 2),
                     round(float(rng.uniform(4, 12)), 2), round(float(rng.uniform(60, 120)), 2),
                     64, 65535, "BENIGN"])
    pd.DataFrame(rows, columns=HEADER).to_csv(path, index=False)


def test_benign_traffic_not_flagged_and_zscores_bounded(tmp_path):
    """Regression: ordinary benign traffic must score LOW infiltration, and no
    displayed z-score may be absurd (the old bug divided by a ~0 std -> ~1e6)."""
    p = os.path.join(tmp_path, "benign.csv")
    _benign_csv(p)
    r = analyze_csv(p)
    scores = r["meta"]["sequenceScores"]["sentinel"]
    assert max(scores) < 0.35, f"benign flagged as attack: max infil {max(scores):.3f}"
    assert r["currentStage"] == "Benign"
    assert r["threatLevel"] in ("Low", "Elevated")
    assert all(abs(a["z"]) <= 8.0 + 1e-6 for a in r["attributions"]), "z-score not bounded"


def test_standardized_inputs_are_clipped():
    """The model must clip standardized inputs so an out-of-distribution feature
    cannot saturate the network (root cause of the benign false positive)."""
    w = LSTMWorldModel.load(os.path.join(ROOT, "models", "world_model.npz"))
    extreme = np.full((1, 8, w.input_dim), 1e9)   # wildly out-of-distribution
    z = w._standardize(extreme)
    assert np.all(np.abs(z) <= w.CLIP + 1e-6)


def _write_min_pcap(path):
    """Craft a tiny classic-pcap (Ethernet/IPv4/TCP) with varied TTL/window/frag."""
    import struct
    def ipv4(src, dst, ttl, payload, frag=0):
        tot = 20 + len(payload)
        h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 1, frag, ttl, 6, 0,
                        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
        return h + payload
    def tcp(sp, dp, flags, win):
        return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, win, 0, 0)
    def eth(pl):
        return struct.pack(">6s6sH", b"\x00" * 6, b"\x11" * 6, 0x0800) + pl
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(30):
            frag = 0x2000 if i % 10 == 0 else 0
            pl = eth(ipv4("45.33.10.7", "10.0.0.50", 64, tcp(40000 + i, 20 + i, 0x02, 1024), frag))
            f.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(pl), len(pl))); f.write(pl)


def test_feature_set_includes_packet_level():
    for f in ("ttl_var", "retrans_ratio", "win_mean", "frag_ratio", "payload_var", "port_scan_score"):
        assert f in FEATURES
    assert len(FEATURES) == 21


def test_pcap_parses_without_scapy(tmp_path):
    """Raw PCAP ingestion must work with the dependency-free parser (no scapy)."""
    from backend.runner import pcap_to_csv
    pcap = os.path.join(tmp_path, "t.pcap"); out = os.path.join(tmp_path, "t.csv")
    _write_min_pcap(pcap)
    pcap_to_csv(pcap, out)
    df = pd.read_csv(out)
    assert len(df) == 30
    for c in ("TTL", "Init Win Bytes Forward", "Frag", "Retrans"):
        assert c in df.columns
    assert df["Frag"].sum() >= 1                    # fragment flags were extracted
    assert (df["Init Win Bytes Forward"] == 1024).all()
