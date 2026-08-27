"""Dependency-light logistic-regression baseline for INFERENCE.

Training fits the model with scikit-learn (pipeline/evaluate.py); its learned
parameters (feature mean/scale + coefficients/intercept) are exported to
models/baseline_np.json. At inference time we reload just those numbers and
evaluate the logistic function in NumPy — so the serving path (offline FastAPI
demo and the Vercel Python function) needs neither scikit-learn nor SciPy,
keeping the deployment small and cold-starts fast. Predictions are bit-identical
to the sklearn model within float tolerance."""
from __future__ import annotations

import json
import numpy as np


class NumpyBaseline:
    def __init__(self, mean, scale, coef, intercept):
        self.mean = np.asarray(mean, dtype=float)
        self.scale = np.asarray(scale, dtype=float)
        self.coef = np.asarray(coef, dtype=float).ravel()
        self.intercept = float(intercept)

    def predict_proba_pos(self, X: np.ndarray) -> np.ndarray:
        """P(class = attack) for rows of X (raw features)."""
        z = (np.atleast_2d(X) - self.mean) / self.scale
        logit = z @ self.coef + self.intercept
        return 1.0 / (1.0 + np.exp(-np.clip(logit, -30, 30)))

    @classmethod
    def from_sklearn(cls, logreg, scaler) -> "NumpyBaseline":
        return cls(scaler.mean_, scaler.scale_, logreg.coef_, logreg.intercept_[0])

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump({"mean": self.mean.tolist(), "scale": self.scale.tolist(),
                       "coef": self.coef.tolist(), "intercept": self.intercept}, f)

    @classmethod
    def load(cls, path: str) -> "NumpyBaseline":
        with open(path) as f:
            d = json.load(f)
        return cls(d["mean"], d["scale"], d["coef"], d["intercept"])
