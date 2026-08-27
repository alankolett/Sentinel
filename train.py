"""Reproducible training entrypoint.

  python train.py

Reads config/train_config.yaml, prepares the dataset (generating the documented
synthetic capture if needed), trains the LSTM world model + logistic baseline on
a leakage-free chronological split with an attack-pattern holdout, evaluates, and
writes all artifacts to models/:
  world_model.npz, baseline.pkl, benchmark.json, train_meta.json
The fixed seed makes this bit-for-bit reproducible.
"""
from __future__ import annotations

import json
import os
import pickle
import numpy as np

from pipeline.evaluate import load_config, prepare, train_models, evaluate

ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(ROOT, "models")


def main():
    cfg = load_config()
    np.random.seed(cfg["seed"])
    print(f"[1/4] preparing dataset ({cfg['data']['source']}) …")
    data = prepare(cfg)
    print(f"      {len(data['feat'])} windows, {len(data['X'])} sequences; "
          f"train={int(data['train_mask'].sum())} test={int(data['test_mask'].sum())} "
          f"(holdout stage: {cfg['split'].get('holdout_stage')})")

    print("[2/4] training LSTM world model + logistic baseline …")
    world, baseline = train_models(cfg, data)

    print("[3/4] evaluating …")
    ev = evaluate(cfg, data, world, baseline)

    os.makedirs(MODELS, exist_ok=True)
    world.save(os.path.join(MODELS, "world_model.npz"))
    with open(os.path.join(MODELS, "baseline.pkl"), "wb") as f:
        pickle.dump(baseline, f)
    # dependency-light baseline for the serving path (no sklearn at inference)
    from models.baseline_np import NumpyBaseline
    NumpyBaseline.from_sklearn(baseline[0], baseline[1]).save(
        os.path.join(MODELS, "baseline_np.json"))
    with open(os.path.join(MODELS, "benchmark.json"), "w") as f:
        json.dump(ev, f, indent=2)
    with open(os.path.join(MODELS, "train_meta.json"), "w") as f:
        json.dump({"config": cfg, "stage_names": data["stage_names"],
                   "features": ev["features"]}, f, indent=2)

    print("[4/4] done. Results:")
    w, b = ev["world"], ev["baseline"]
    print(f"      world     F1={w['f1']:.3f} P={w['precision']:.3f} R={w['recall']:.3f} "
          f"AUC={w['roc_auc']:.3f} FPR={w['fpr']:.3f}")
    print(f"      baseline  F1={b['f1']:.3f} P={b['precision']:.3f} R={b['recall']:.3f} "
          f"AUC={b['roc_auc']:.3f} FPR={b['fpr']:.3f}")
    print(f"      forecast lead: +{ev['lead_seconds']}s ({ev['lead_windows']} windows)")
    if ev["holdout"]:
        h = ev["holdout"]
        print(f"      unseen-stage [{h['stage']}] recall: world={h['world_recall']:.3f} "
              f"baseline={h['baseline_recall']:.3f}")


if __name__ == "__main__":
    main()
