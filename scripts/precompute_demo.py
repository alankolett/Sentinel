"""Precompute the REAL model's analysis of the bundled demo capture and copy the
REAL benchmark, into public/real/ as static JSON. This lets the statically hosted
site (Vercel, no Python running) serve genuine trained-model output for the
default experience — not client-side heuristics. The Python API, when running,
overrides these with live inference on user uploads.

  python scripts/precompute_demo.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "public", "real")


def main() -> None:
    from backend.infer import analyze_csv, benchmark
    os.makedirs(OUT, exist_ok=True)
    demo_csv = os.path.join(ROOT, "data", "demo_capture.csv")
    result = analyze_csv(demo_csv)
    result["source"] = "Synthetic infiltration capture · CIC-IDS schema · CIC-IDS2018-trained model"
    with open(os.path.join(OUT, "demo.json"), "w") as f:
        json.dump(result, f, separators=(",", ":"))
    with open(os.path.join(OUT, "benchmark.json"), "w") as f:
        json.dump(benchmark(), f, separators=(",", ":"))
    shutil.copy(os.path.join(ROOT, "models", "train_meta.json"),
                os.path.join(OUT, "train_meta.json"))
    print(f"wrote {OUT}/demo.json, benchmark.json, train_meta.json")


if __name__ == "__main__":
    main()
