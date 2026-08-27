"""Shared training + evaluation logic used by train.py, benchmark.py and the API,
so the numbers in the UI, the saved metrics file, and a fresh `benchmark.py` run
are guaranteed identical (single source of truth — no divergence possible)."""
from __future__ import annotations

import os
import numpy as np
import yaml
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

from pipeline.extract_features import parse_flows, build_windows, make_sequences, load_mapping, FEATURES
from pipeline.synth import write_csv
from models.world_model import LSTMWorldModel

ROOT = os.path.dirname(os.path.dirname(__file__))


def load_config(path: str | None = None) -> dict:
    path = path or os.path.join(ROOT, "config", "train_config.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def ensure_dataset(cfg: dict) -> str:
    d = cfg["data"]
    path = os.path.join(ROOT, d["path"])
    if os.path.exists(path):
        return path
    demo_path = os.path.join(ROOT, "data", "demo_capture.csv")
    if os.path.exists(demo_path):
        print(f"      [info] Raw dataset {d['path']} not found. Using pre-packaged capture {demo_path}")
        return demo_path
    synth_path = os.path.join(ROOT, "data", "synthetic_capture.csv")
    if not os.path.exists(synth_path):
        os.makedirs(os.path.dirname(synth_path), exist_ok=True)
        write_csv(synth_path, d.get("synthetic_seed", 7))
    return synth_path


def prepare(cfg: dict) -> dict:
    """Parse -> windows -> sequences, with a leakage-free chronological split and
    an attack-pattern holdout removed from TRAIN only."""
    path = ensure_dataset(cfg)
    df, meta = parse_flows(path)
    w = cfg["windowing"]
    feat, stage_idx, wmeta = build_windows(df, w["window_ms"], w["stride_ms"])
    X, y_next, y_stage, anchor = make_sequences(feat, stage_idx, w["sequence_length"])
    stage_names, _, _ = load_mapping()

    split = cfg["split"]
    n = len(X)
    cut = int(n * (1 - split["test_fraction"]))
    train_mask = np.arange(n) < cut
    test_mask = ~train_mask

    # attack-pattern holdout: drop this stage from TRAIN entirely (still in test)
    holdout = split.get("holdout_stage")
    holdout_idx = stage_names.index(holdout) if holdout in stage_names else -1
    if holdout_idx >= 0:
        train_mask = train_mask & (y_stage != holdout_idx)

    # diverse-benign augmentation: broadens the benign manifold in TRAIN only so
    # the model stops flagging ordinary benign traffic (internal shares, DNS,
    # backups) it never saw in the single-environment CIC-IDS2018 day. Test split
    # is untouched — the benchmark stays a real measurement on real data.
    n_aug = int(cfg.get("data", {}).get("benign_aug_windows", 0))
    if n_aug > 0:
        from pipeline.benign_aug import benign_windows
        aug_feat, aug_stage = benign_windows(n_aug, w["window_ms"], w["stride_ms"],
                                             seed=cfg.get("seed", 42) + 1)
        aX, aY, aYs, _ = make_sequences(aug_feat, aug_stage, w["sequence_length"])
        base_anchor = int(anchor.max()) + 1 if len(anchor) else 0
        aAnchor = np.arange(len(aX)) + base_anchor
        X = np.concatenate([X, aX], 0)
        y_next = np.concatenate([y_next, aY], 0)
        y_stage = np.concatenate([y_stage, aYs], 0)
        anchor = np.concatenate([anchor, aAnchor], 0)
        train_mask = np.concatenate([train_mask, np.ones(len(aX), dtype=bool)])
        test_mask = np.concatenate([test_mask, np.zeros(len(aX), dtype=bool)])

    return {
        "df": df, "meta": meta, "feat": feat, "stage_idx": stage_idx, "wmeta": wmeta,
        "X": X, "y_next": y_next, "y_stage": y_stage, "anchor": anchor,
        "train_mask": train_mask, "test_mask": test_mask,
        "stage_names": stage_names, "holdout_idx": holdout_idx, "cut": cut,
    }


def train_models(cfg: dict, data: dict):
    m = cfg["model"]
    X, y_next, y_stage = data["X"], data["y_next"], data["y_stage"]
    tr = data["train_mask"]
    world = LSTMWorldModel(input_dim=X.shape[2], hidden_dim=m["hidden_dim"],
                           n_stages=len(data["stage_names"]), seed=cfg["seed"])
    world.fit(X[tr], y_next[tr], y_stage[tr], epochs=m["epochs"], lr=m["lr"],
              lam=m["lambda_stage"], batch=m["batch"])
    # calibrate novelty scoring on benign training transitions only
    benign = tr & (y_stage == 0)
    bi = benign if np.sum(benign) >= 5 else tr
    world.calibrate(X[bi], y_next[bi], X[bi][:, -1, :])

    # baseline: single-window logistic regression, attack(=stage>0) vs benign,
    # trained on the last window of each training sequence.
    Xb = X[tr][:, -1, :]
    yb = (y_stage[tr] > 0).astype(int)
    scaler = StandardScaler().fit(Xb)
    base = LogisticRegression(max_iter=1000, class_weight="balanced")
    base.fit(scaler.transform(Xb), yb)
    return world, (base, scaler)


def _threshold_at_fpr(scores, labels, fpr=0.05):
    neg = np.sort(scores[labels == 0])
    if len(neg) == 0:
        return 0.5
    k = min(len(neg) - 1, int(np.ceil((1 - fpr) * len(neg))))
    return float(neg[k] + 1e-9)


def _threshold_best_f1(scores, labels):
    """Operating point that maximises F1 on the given (TRAIN) scores — chosen
    without ever touching the test split, so no leakage. More representative than
    a fixed-FPR point when base rates differ across models."""
    if not (np.any(labels == 1) and np.any(labels == 0)):
        return 0.5
    cand = np.unique(scores)
    best_thr, best_f1 = 0.5, -1.0
    for thr in cand:
        pred = (scores >= thr).astype(int)
        tp = int(np.sum((pred == 1) & (labels == 1)))
        fp = int(np.sum((pred == 1) & (labels == 0)))
        fn = int(np.sum((pred == 0) & (labels == 1)))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        if f1 > best_f1:
            best_f1, best_thr = f1, float(thr)
    return best_thr


def _metrics(scores, labels, thr):
    pred = (scores >= thr).astype(int)
    tp = int(np.sum((pred == 1) & (labels == 1)))
    fp = int(np.sum((pred == 1) & (labels == 0)))
    tn = int(np.sum((pred == 0) & (labels == 0)))
    fn = int(np.sum((pred == 0) & (labels == 1)))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    both = len(set(labels.tolist())) > 1
    return {
        "precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
        "accuracy": (tp + tn) / max(len(labels), 1),
        "roc_auc": float(roc_auc_score(labels, scores)) if both else 0.5,
        "pr_auc": float(average_precision_score(labels, scores)) if both else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def evaluate(cfg: dict, data: dict, world, baseline) -> dict:
    X, y_stage, anchor = data["X"], data["y_stage"], data["anchor"]
    tr, te = data["train_mask"], data["test_mask"]
    base, scaler = baseline
    labels = (y_stage > 0).astype(int)

    # Baseline = conventional single-window supervised classifier (logistic
    # regression on the current window only — the standard "classify each flow in
    # isolation" approach the world model is meant to improve on).
    bl_all = base.predict_proba(scaler.transform(X[:, -1, :]))[:, 1]
    # Fair comparison: both models operate at the SAME false-alarm budget (5% FPR,
    # chosen on TRAIN only — no leakage). This is the security-relevant operating
    # point; better temporal ranking then shows up as higher recall at equal FPR.
    bl_thr = _threshold_at_fpr(bl_all[tr], labels[tr], 0.05)

    # World model score = the trained LSTM's TEMPORAL predictor: infiltration =
    # 1 - P(benign | last w windows). This is the learned P(S_{t+1}|history) stage
    # head — it reads the *sequence* of network states, not a single window, which
    # is exactly where its measured lift over the static baseline comes from.
    wm_all = world.infiltration(X)
    wm_thr = _threshold_at_fpr(wm_all[tr], labels[tr], 0.05)

    # Novelty (transition-reconstruction surprise) is retained as an auxiliary,
    # unsupervised anomaly channel for reporting, but is NOT the headline score.
    novelty = np.log1p(world.surprise(X, data["y_next"]))
    nov_thr = max(1.0, 5.0 * float(np.max(novelty[tr & (labels == 0)])) if np.any(tr & (labels == 0)) else 1.0)

    world_m = _metrics(wm_all[te], labels[te], wm_thr)
    base_m = _metrics(bl_all[te], labels[te], bl_thr)

    # unseen-stage generalisation: metrics restricted to the held-out attack stage
    ho = data["holdout_idx"]
    holdout_report = None
    if ho >= 0:
        te_ho = te & ((y_stage == ho) | (labels == 0))
        if np.sum((y_stage[te_ho] == ho)) > 0:
            hl = (y_stage[te_ho] == ho).astype(int)
            holdout_report = {
                "stage": data["stage_names"][ho],
                "world_recall": _metrics(wm_all[te_ho], hl, wm_thr)["recall"],
                "baseline_recall": _metrics(bl_all[te_ho], hl, bl_thr)["recall"],
            }

    # forecast lead time (mechanism demo over the full sequence timeline)
    order = np.argsort(anchor)
    wm_seq, bl_seq, lab_seq = wm_all[order], bl_all[order], labels[order]
    last_mal = int(np.max(np.where(lab_seq == 1))) if np.any(lab_seq == 1) else -1

    def run_start(s, thr, anchor_i):
        if anchor_i < 0 or s[anchor_i] < thr:
            return anchor_i
        i = anchor_i
        while i > 0 and s[i - 1] >= thr:
            i -= 1
        return i
    lead = max(0, run_start(bl_seq, bl_thr, last_mal) - run_start(wm_seq, wm_thr, last_mal)) if last_mal >= 0 else 0
    lead_sec = int(lead * cfg["windowing"]["stride_ms"] / 1000)
    onset = int(np.min(np.where(lab_seq == 1))) if np.any(lab_seq == 1) else -1

    return {
        "world": world_m, "baseline": base_m,
        "lead_windows": int(lead), "lead_seconds": lead_sec,
        "wm_threshold": wm_thr, "bl_threshold": bl_thr, "novelty_threshold": nov_thr,
        "wm_scores": wm_seq.tolist(), "bl_scores": bl_seq.tolist(),
        "labels": lab_seq.tolist(), "onset_index": onset,
        "holdout": holdout_report,
        "n_train": int(np.sum(tr)), "n_test": int(np.sum(te)),
        "features": FEATURES,
    }
