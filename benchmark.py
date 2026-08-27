"""Regenerate the world-model-vs-baseline comparison table from a single command
and assert it matches the figures the API serves (models/benchmark.json). If they
diverge, that is an immediate credibility failure — this script is the guard.

  python benchmark.py
"""
from __future__ import annotations

import json
import os

from pipeline.evaluate import load_config, prepare, train_models, evaluate

ROOT = os.path.dirname(os.path.abspath(__file__))


def fmt(m):
    return (f"F1={m['f1']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  "
            f"AUC={m['roc_auc']:.3f}  PR-AUC={m['pr_auc']:.3f}  FPR={m['fpr']:.3f}")


def main():
    cfg = load_config()
    data = prepare(cfg)
    world, base = train_models(cfg, data)
    ev = evaluate(cfg, data, world, base)

    print("\n  Sentinel world model vs logistic-regression baseline")
    print("  chronological hold-out, unseen-stage generalisation\n")
    print(f"  {'Sentinel (world model)':30s} {fmt(ev['world'])}")
    print(f"  {'Baseline (logistic reg.)':30s} {fmt(ev['baseline'])}")
    print(f"\n  Forecast lead: +{ev['lead_seconds']}s ({ev['lead_windows']} windows)")
    if ev["holdout"]:
        h = ev["holdout"]
        print(f"  Unseen stage [{h['stage']}] recall: "
              f"world={h['world_recall']:.3f}  baseline={h['baseline_recall']:.3f}")

    saved_path = os.path.join(ROOT, "models", "benchmark.json")
    if os.path.exists(saved_path):
        saved = json.load(open(saved_path))
        drift = abs(saved["world"]["f1"] - ev["world"]["f1"])
        status = "OK — matches served figures" if drift < 1e-9 else f"MISMATCH (Δf1={drift:.2e}) — retrain"
        print(f"\n  Reproducibility vs models/benchmark.json: {status}")
        assert drift < 1e-9, "benchmark.json is stale; run `python train.py`"
    print()


if __name__ == "__main__":
    main()
