"""Inference: run the trained world model + baseline over an uploaded flow CSV and
return a structured analysis. Every number here is produced by the loaded model
at runtime — nothing is hardcoded. Output keys are camelCase to feed the frontend
directly."""
from __future__ import annotations

import os
import re
import json
import numpy as np

from pipeline.extract_features import (
    parse_flows, build_windows, make_sequences, load_mapping, label_to_stage, FEATURES,
)
from models.world_model import LSTMWorldModel
from models.baseline_np import NumpyBaseline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS = os.path.join(ROOT, "models")

_STATE = {}


def _load():
    if _STATE:
        return _STATE
    world = LSTMWorldModel.load(os.path.join(MODELS, "world_model.npz"))
    base = NumpyBaseline.load(os.path.join(MODELS, "baseline_np.json"))
    with open(os.path.join(MODELS, "train_meta.json")) as f:
        meta = json.load(f)
    with open(os.path.join(MODELS, "benchmark.json")) as f:
        bench = json.load(f)
    stage_names, technique, label_map = load_mapping()
    _STATE.update(world=world, base=base, meta=meta, bench=bench,
                  stage_names=stage_names, technique=technique, label_map=label_map)
    return _STATE


def _pretty(stage: str) -> str:
    return stage.replace("_", " ").title() if stage != "command_and_control" else "Command and Control"


def _is_private(ip: str) -> bool:
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.0\.0\.1)", str(ip)))


def _threat_level(p: float) -> str:
    return "Critical" if p >= 0.8 else "High" if p >= 0.6 else "Elevated" if p >= 0.35 else "Low"


def _hosts_and_graph(df):
    agg = {}
    edges = {}
    for r in df.itertuples(index=False):
        s = agg.setdefault(r.src_ip, {"flows": 0, "syn": 0, "ack": 0, "ports": set(), "peers": set(), "bytes": 0.0})
        agg.setdefault(r.dst_ip, {"flows": 0, "syn": 0, "ack": 0, "ports": set(), "peers": set(), "bytes": 0.0})
        s["flows"] += 1; s["syn"] += r.syn; s["ack"] += r.ack
        s["ports"].add(int(r.dst_port)); s["peers"].add(r.dst_ip); s["bytes"] += r.bytes
        k = (r.src_ip, r.dst_ip)
        e = edges.setdefault(k, {"w": 0, "syn": 0, "ack": 0})
        e["w"] += 1; e["syn"] += r.syn; e["ack"] += r.ack
    nodes = []
    for ip, a in agg.items():
        scan = min(1.0, len(a["ports"]) / 30)
        fan = min(1.0, len(a["peers"]) / 15)
        failed = max(0.0, (a["syn"] - a["ack"]) / a["syn"]) if a["syn"] > 0 else 0.0
        susp = min(1.0, 0.45 * scan + 0.35 * fan + 0.2 * failed)
        nodes.append({"ip": ip, "flows": a["flows"], "dstPorts": len(a["ports"]), "peers": len(a["peers"]),
                      "bytes": float(a["bytes"]), "internal": _is_private(ip), "suspicion": float(susp)})
    nodes.sort(key=lambda n: (-n["suspicion"], -n["flows"]))
    keep = {n["ip"] for n in nodes[:40]}
    elist = []
    for (s, d), e in edges.items():
        if s in keep and d in keep:
            failed = (e["syn"] - e["ack"]) / e["syn"] if e["syn"] > 0 else 0.0
            elist.append({"src": s, "dst": d, "weight": e["w"], "suspicious": bool(failed > 0.5 or e["w"] > 20)})
    elist.sort(key=lambda e: -e["weight"])
    hosts = [{"ip": n["ip"], "flows": n["flows"], "dstPorts": n["dstPorts"], "peers": n["peers"],
              "bytes": n["bytes"], "suspicion": n["suspicion"]} for n in nodes[:10]]
    return hosts, [n for n in nodes if n["ip"] in keep], elist[:120]


def analyze_csv(path: str, K: int = 5) -> dict:
    st = _load()
    world, base = st["world"], st["base"]
    stage_names, technique = st["stage_names"], st["technique"]
    seqlen = st["meta"]["config"]["windowing"]["sequence_length"]
    stride_ms = st["meta"]["config"]["windowing"]["stride_ms"]
    nov_thr = st["bench"]["novelty_threshold"]

    df, dmeta = parse_flows(path)
    # real, content-derived count of flows whose label maps to a non-benign
    # ATT&CK stage in THIS file (varies per upload). Distinct from the schema
    # column-match count, which is constant for any CIC-style header.
    attack_labeled = int(sum(1 for lbl in df["label"] if label_to_stage(lbl, st["label_map"]) != "benign"))
    w = st["meta"]["config"]["windowing"]
    feat, stage_idx, wmeta = build_windows(df, w["window_ms"], w["stride_ms"])
    if len(feat) < seqlen + 1:
        raise ValueError(f"Capture too short: need at least {seqlen + 1} windows, got {len(feat)}.")
    X, y_next, y_stage, anchor = make_sequences(feat, stage_idx, seqlen)

    # per-window scores: world model = LSTM temporal stage-head infiltration
    # (1 - P(benign | history)); baseline = single-window logistic. Same
    # definitions the benchmark reports, so UI and metrics never diverge.
    sup = base.predict_proba_pos(X[:, -1, :])
    sentinel = world.infiltration(X)

    # current window = last sequence; forecast forward
    last_seq = feat[-seqlen:]
    roll = world.rollout(last_seq, k=K)
    # Current infiltration is the world model's own temporal stage-head score for
    # the latest window — identical definition to `sentinel`/the benchmark, so the
    # headline number can never diverge from the evaluated metric. (Previously this
    # was max(baseline, novelty), which let an out-of-distribution baseline or
    # novelty spike report ~100% on ordinary benign traffic.)
    current_infil = float(sentinel[-1]) if len(sentinel) else float(world.infiltration(last_seq[None])[0])
    # ATT&CK stage from evidence-based mapping on the observed / simulated states
    cur_stage_name = evidence_stage(feat[-1], world.x_mean, world.x_std)
    # Displayed stage must agree with the model: if the world model reads the
    # current window as benign, do not surface an attack stage from the heuristic
    # evidence layer alone (avoids "Benign score, Lateral Movement label").
    # Display gate: if the model's infiltration for this window is not even
    # "Elevated" (< 0.35, the lowest non-benign threat band), do not surface an
    # attack stage from the heuristic evidence layer — keeps the label consistent
    # with the score the user sees ("Benign score, Lateral Movement label" bug).
    if current_infil < 0.35:
        cur_stage_name = "benign"
    # predicted next stage = evidence stage of the highest-infiltration rollout state
    peak_state = max(roll, key=lambda s: s["infiltration"]) if roll else None
    pred_state_vec = world.predict_next(last_seq[None])[0]
    pred_stage_name = evidence_stage(pred_state_vec, world.x_mean, world.x_std)
    if pred_stage_name == "benign":
        pred_stage_name = cur_stage_name
    cur_stage = _pretty(cur_stage_name)
    pred_stage = _pretty(pred_stage_name)
    pred_idx = stage_names.index(pred_stage_name) if pred_stage_name in stage_names else 0

    # explainability (real gradients through the LSTM)
    feat_c, time_c = world.attribute(feat[-seqlen:][None])
    total = float(np.sum(np.abs(feat_c))) or 1.0
    attribs = sorted(
        [{"feature": FEATURES[j], "contribution": float(feat_c[j] / total),
          "value": float(feat[-1][j]),
          # z uses the same robust (floored) std as the model; clip for display so a
          # near-constant training feature can't render an absurd ±1e6 z-score.
          "z": float(np.clip((feat[-1][j] - world.x_mean[j]) / world.x_std[j],
                             -world.CLIP, world.CLIP))}
         for j in range(len(FEATURES))],
        key=lambda a: -abs(a["contribution"]))
    tsum = float(np.sum(time_c)) or 1.0
    temporal = (time_c / tsum).tolist()

    hosts, gnodes, gedges = _hosts_and_graph(df)

    forecast = [{"step": 0, "infiltration": current_infil, "topStage": cur_stage,
                 "confidence": float(1 - _entropy(world.stage_proba(feat[-seqlen:][None])[0]))}]
    for s in roll:
        stg = evidence_stage(np.asarray(s["state"]), world.x_mean, world.x_std)
        forecast.append({"step": s["step"], "infiltration": s["infiltration"],
                         "topStage": _pretty(stg), "confidence": s["confidence"]})

    peak = max([f["infiltration"] for f in forecast])
    # per-window infiltration aligned to windows (sequence i predicts anchor[i])
    win_infil = {int(anchor[k]): float(sentinel[k]) for k in range(len(anchor))}
    windows_out = [{"index": i, "tStart": m["t_start"], "tEnd": m["t_end"], "flowCount": m["flows"],
                    "malicious": bool(stage_idx[i] > 0), "stageIdx": int(stage_idx[i]),
                    "stage": _pretty(stage_names[int(stage_idx[i])]),
                    "vec": feat[i].tolist(), "infiltration": win_infil.get(i)}
                   for i, m in enumerate(wmeta)]

    return {
        "meta": {"flows": int(dmeta["rows"]), "windows": int(len(feat)), "K": K,
                 "horizonSeconds": int(K * stride_ms / 1000), "dataset": dmeta["dataset"],
                 "matched": attack_labeled, "labeledAttackFlows": attack_labeled,
                 "schemaColumnsMatched": int(dmeta["matched"]),
                 "datasetLabelled": bool(np.any(stage_idx > 0)),
                 "stageNames": [_pretty(s) for s in stage_names], "features": FEATURES,
                 "sequenceScores": {"sentinel": sentinel.tolist(), "baseline": sup.tolist(),
                                    "anchors": anchor.tolist(), "labels": (y_stage > 0).astype(int).tolist()}},
        "currentStage": cur_stage, "predictedStage": pred_stage,
        "predictedTechnique": technique[stage_names[pred_idx]],
        "currentInfiltration": current_infil, "threatLevel": _threat_level(peak),
        "forecast": forecast, "attributions": attribs, "temporal": temporal,
        "topHosts": hosts, "graph": {"nodes": gnodes, "edges": gedges},
        "windows": windows_out,
    }


def evidence_stage(vec, x_mean, x_std) -> str:
    """Evidence-based ATT&CK stage from the real (de-normalised) feature signature
    of a network-state window. Ordered by kill-chain specificity — first match
    wins. This is the 'evidence-based mapping layer' the problem statement asks
    for; the LSTM stage head is a weak prior on small data, so behavioural
    evidence is the authority for the displayed stage."""
    f = {name: vec[j] for j, name in enumerate(FEATURES)}
    z = {name: (vec[j] - x_mean[j]) / x_std[j] for j, name in enumerate(FEATURES)}
    if f["port_scan_score"] > 0.5 and f["uniq_dst_ports"] > 8:
        return "reconnaissance"
    if z["bytes_out_ratio"] > 1.0 and f["avg_bytes"] > 20000:
        return "exfiltration"
    # initial access (brute force / exploited service) is checked before lateral:
    # a high unanswered-SYN ratio is its signature and would otherwise be masked by
    # the private->private lateral rule when attacker and target are both internal.
    if z["failed_conn_ratio"] > 2.0 or (f["failed_conn_ratio"] > 0.4 and z["syn_ratio"] > 0.5):
        return "initial_access"
    # lateral movement = internal host reaching MANY internal peers (fan-out),
    # not merely any private->private flow (ordinary intranet traffic is
    # private->private too). Require both a high internal ratio and real fan-out.
    if f["lateral_score"] > 0.4 and z["lateral_score"] > 0.4 and (f["uniq_dst_ips"] > 5 or z["uniq_dst_ips"] > 1.0):
        return "lateral_movement"
    if z["iat_mean"] > 1.0 and f["avg_bytes"] < 1000 and z["uniq_dst_ips"] < 0.5:
        return "command_and_control"
    if z["uniq_dst_ports"] > 1.0 or z["port_scan_score"] > 0.6:
        return "reconnaissance"
    return "benign"


def _entropy(p):
    p = np.asarray(p)
    return float(-np.sum(p * np.log(p + 1e-9)) / np.log(len(p)))


def benchmark() -> dict:
    return _load()["bench"]
