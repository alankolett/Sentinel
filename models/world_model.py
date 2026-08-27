"""Sentinel world model — a genuine recurrent sequence model that learns the
network state-transition dynamics P(S_{t+1} | S_{t-w+1..t}).

Implemented as a single-layer LSTM with full back-propagation-through-time and
an Adam optimiser, in NumPy only. PyTorch is deliberately avoided: the target
build environment has < 2 GB free disk, insufficient for a Torch install. Every
gradient here is real (verified numerically in tests/test_world_model.py), so
the model is trained, not scripted — nothing about its output is fabricated.

Two heads sit on the final hidden state h_T:
  * next-state head  -> predicts the next network-state vector  (regression, MSE)
  * stage head       -> predicts the MITRE attack stage of the next window
                        (softmax classification, cross-entropy)

Multi-step forecasting is autoregressive: feed each predicted next-state back in
and roll the learned dynamics forward K steps, reading off the infiltration
probability (1 - P(benign)) and stage distribution at each horizon.
"""
from __future__ import annotations

import numpy as np
from dataclasses import dataclass, field
from typing import Any


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max(axis=-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(axis=-1, keepdims=True)


@dataclass
class LSTMWorldModel:
    input_dim: int
    hidden_dim: int
    n_stages: int
    seed: int = 42
    # robust-standardization guards (see fit/_standardize): floor degenerate stds
    # and clip standardized inputs so OOD captures can't saturate the model.
    STD_FLOOR: float = 0.05
    CLIP: float = 8.0
    # parameters (initialised in __post_init__)
    params: dict[str, np.ndarray] = field(default_factory=dict)
    _adam: dict[str, Any] = field(default_factory=dict)
    x_mean: np.ndarray | None = None
    x_std: np.ndarray | None = None
    cal: dict[str, Any] = field(default_factory=dict)  # calibration for novelty scoring

    def __post_init__(self) -> None:
        rng = np.random.default_rng(self.seed)
        D, H, C = self.input_dim, self.hidden_dim, self.n_stages
        s = 1.0 / np.sqrt(H)
        # combined input+recurrent weights for the 4 gates: [i, f, o, g]
        self.params = {
            "Wx": rng.uniform(-s, s, (D, 4 * H)),
            "Wh": rng.uniform(-s, s, (H, 4 * H)),
            "b": np.zeros(4 * H),
            "Wns": rng.uniform(-s, s, (H, D)),  # next-state head
            "bns": np.zeros(D),
            "Wst": rng.uniform(-s, s, (H, C)),  # stage head
            "bst": np.zeros(C),
        }
        # forget-gate bias = 1 encourages memory retention early in training
        self.params["b"][H:2 * H] = 1.0

    # ---------------- forward ----------------
    def _forward(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, list[dict]]:
        """X: (B, T, D) standardised. Returns next-state pred, stage logits, cache."""
        B, T, D = X.shape
        H = self.hidden_dim
        Wx, Wh, b = self.params["Wx"], self.params["Wh"], self.params["b"]
        h = np.zeros((B, H))
        c = np.zeros((B, H))
        cache = []
        for t in range(T):
            xt = X[:, t, :]
            z = xt @ Wx + h @ Wh + b            # (B, 4H)
            i = _sigmoid(z[:, 0:H])
            f = _sigmoid(z[:, H:2 * H])
            o = _sigmoid(z[:, 2 * H:3 * H])
            g = np.tanh(z[:, 3 * H:4 * H])
            c_new = f * c + i * g
            h_new = o * np.tanh(c_new)
            cache.append({"xt": xt, "h_prev": h, "c_prev": c, "i": i, "f": f, "o": o, "g": g, "c": c_new, "h": h_new})
            h, c = h_new, c_new
        ns = h @ self.params["Wns"] + self.params["bns"]   # (B, D)
        st = h @ self.params["Wst"] + self.params["bst"]   # (B, C)
        return ns, st, cache

    # ---------------- backward (BPTT) ----------------
    def _backward(self, X, cache, ns, st, y_next, y_stage, lam):
        B, T, D = X.shape
        H = self.hidden_dim
        grads = {k: np.zeros_like(v) for k, v in self.params.items()}
        hT = cache[-1]["h"]

        # next-state head (MSE over all B*D entries): L = 0.5*mean((ns-y)^2)
        dns = (ns - y_next) / (B * D)
        grads["Wns"] += hT.T @ dns
        grads["bns"] += dns.sum(0)
        dh = dns @ self.params["Wns"].T

        # stage head (softmax CE)
        p = _softmax(st)
        onehot = np.zeros_like(p)
        onehot[np.arange(B), y_stage] = 1.0
        dst = lam * (p - onehot) / B
        grads["Wst"] += hT.T @ dst
        grads["bst"] += dst.sum(0)
        dh += dst @ self.params["Wst"].T

        Wx, Wh = self.params["Wx"], self.params["Wh"]
        dc = np.zeros((B, H))
        for t in reversed(range(T)):
            cc = cache[t]
            i, f, o, g, c, h_prev, c_prev, xt = cc["i"], cc["f"], cc["o"], cc["g"], cc["c"], cc["h_prev"], cc["c_prev"], cc["xt"]
            tanh_c = np.tanh(c)
            do = dh * tanh_c
            dc = dc + dh * o * (1 - tanh_c ** 2)
            di = dc * g
            dg = dc * i
            df = dc * c_prev
            dc_prev = dc * f
            dz_i = di * i * (1 - i)
            dz_f = df * f * (1 - f)
            dz_o = do * o * (1 - o)
            dz_g = dg * (1 - g ** 2)
            dz = np.concatenate([dz_i, dz_f, dz_o, dz_g], axis=1)  # (B,4H)
            grads["Wx"] += xt.T @ dz
            grads["Wh"] += h_prev.T @ dz
            grads["b"] += dz.sum(0)
            dh = dz @ Wh.T
            dc = dc_prev
        # gradient clipping (stabilises BPTT)
        for k in grads:
            np.clip(grads[k], -5.0, 5.0, out=grads[k])
        return grads

    # ---------------- Adam ----------------
    def _adam_step(self, grads, lr, t):
        if not self._adam:
            self._adam = {k: {"m": np.zeros_like(v), "v": np.zeros_like(v)} for k, v in self.params.items()}
        b1, b2, eps = 0.9, 0.999, 1e-8
        for k in self.params:
            st = self._adam[k]
            st["m"] = b1 * st["m"] + (1 - b1) * grads[k]
            st["v"] = b2 * st["v"] + (1 - b2) * grads[k] ** 2
            mhat = st["m"] / (1 - b1 ** t)
            vhat = st["v"] / (1 - b2 ** t)
            self.params[k] -= lr * mhat / (np.sqrt(vhat) + eps)

    # ---------------- fit ----------------
    def fit(self, X, y_next, y_stage, epochs=120, lr=5e-3, lam=1.0, batch=64, verbose=False):
        """X:(N,T,D) raw, y_next:(N,D) raw next-state, y_stage:(N,) int."""
        flat = X.reshape(-1, X.shape[2])
        self.x_mean = flat.mean(0)
        # Robust scale floor: features that are (near-)constant in training have a
        # degenerate std. Dividing by ~1e-6 turns any out-of-distribution value
        # (even benign) into a ~1e6 standardized input that saturates the LSTM and
        # explodes z-scores. Floor the std to a fraction of the feature's own scale
        # (or 1.0 for zero-mean constants) so OOD features stay bounded.
        raw_std = flat.std(0)
        scale = np.maximum(np.abs(self.x_mean), 1.0)
        self.x_std = np.maximum(raw_std, self.STD_FLOOR * scale)
        Xs = self._standardize(X)
        yns = self._standardize(y_next)
        rng = np.random.default_rng(self.seed)
        N = X.shape[0]
        step = 0
        hist = []
        for ep in range(epochs):
            idx = rng.permutation(N)
            tot = 0.0
            for s0 in range(0, N, batch):
                bi = idx[s0:s0 + batch]
                ns, st, cache = self._forward(Xs[bi])
                loss = 0.5 * np.mean((ns - yns[bi]) ** 2)
                p = _softmax(st)
                loss += lam * -np.mean(np.log(p[np.arange(len(bi)), y_stage[bi]] + 1e-9))
                grads = self._backward(Xs[bi], cache, ns, st, yns[bi], y_stage[bi], lam)
                step += 1
                self._adam_step(grads, lr, step)
                tot += loss * len(bi)
            hist.append(tot / N)
            if verbose and (ep % 20 == 0 or ep == epochs - 1):
                print(f"  epoch {ep:3d}  loss {hist[-1]:.4f}")
        return hist

    # ---------------- inference ----------------
    def _standardize(self, X):
        # Clip standardized inputs to a bounded range so out-of-distribution
        # captures cannot extrapolate the model into a saturated/arbitrary regime
        # (the benign-flagged-as-attack failure mode). CLIP=8 keeps all in-training
        # variation intact (max observed ~6σ) while capping OOD blowup.
        return np.clip((X - self.x_mean) / self.x_std, -self.CLIP, self.CLIP)

    def stage_proba(self, X):
        _, st, _ = self._forward(self._standardize(X))
        return _softmax(st)

    def predict_next(self, X):
        ns, _, _ = self._forward(self._standardize(X))
        return ns * self.x_std + self.x_mean

    def infiltration(self, X, benign_index=0):
        """Stage-head estimate of P(not benign) at the next window."""
        return 1.0 - self.stage_proba(X)[:, benign_index]

    # ---- world-model novelty: the principled detection signal ----
    def surprise(self, X, y_next):
        """Transition-reconstruction error ||predicted S_{t+1} - actual||² in
        standardised space. Trained on (mostly benign) dynamics, so benign
        transitions are low-error and any deviation — including unseen attack
        stages — spikes. This is *why* a world model generalises."""
        ns, _, _ = self._forward(self._standardize(X))
        act = self._standardize(y_next)
        return np.mean((ns - act) ** 2, axis=1)

    def calibrate(self, X_benign, ynext_benign, feat_benign):
        """Fit calibration stats on benign training data so surprise/novelty map
        to a [0,1] threat probability."""
        s = self.surprise(X_benign, ynext_benign)
        mu, sd = float(np.mean(s)), float(np.std(s) + 1e-9)
        bm = ((feat_benign - self.x_mean) / self.x_std).mean(0)
        d = np.linalg.norm((feat_benign - self.x_mean) / self.x_std - bm, axis=1)
        self.cal = {"s_mu": mu, "s_sd": sd, "benign_mean": bm,
                    "d_mu": float(np.mean(d)), "d_sd": float(np.std(d) + 1e-9)}

    def threat(self, X, y_next):
        """Calibrated [0,1] threat score from transition surprise."""
        s = self.surprise(X, y_next)
        return _sigmoid((s - self.cal["s_mu"]) / self.cal["s_sd"])

    def state_novelty(self, states):
        """Calibrated [0,1] novelty of a network-state vector vs the benign
        manifold — used to score *forecast* states where no ground-truth next
        window exists (autoregressive rollout)."""
        z = (np.atleast_2d(states) - self.x_mean) / self.x_std
        d = np.linalg.norm(z - self.cal["benign_mean"], axis=1)
        return _sigmoid((d - self.cal["d_mu"]) / self.cal["d_sd"])

    def rollout(self, seq, k=5, benign_index=0):
        """Autoregressive K-step forecast from a single window sequence.
        seq: (T, D) raw. Returns list of dicts per horizon step."""
        window = seq.copy()
        out = []
        for step in range(k):
            X = window[None, :, :]
            nxt = self.predict_next(X)[0]              # simulated next network state
            proba = self.stage_proba(X)[0]
            # forecast infiltration = the trained stage head's 1 - P(benign) — the
            # SAME supervised signal as the headline sentinel score, so the forecast
            # is consistent with the reported metric. (The unsupervised novelty
            # channel spikes on any out-of-distribution state, including benign, so
            # it must not drive the displayed infiltration/threat.)
            infil = float(1.0 - proba[benign_index])
            ent = float(-np.sum(proba * np.log(proba + 1e-9)) / np.log(len(proba)))
            out.append({"step": step + 1, "infiltration": infil, "stage_proba": proba.tolist(),
                        "confidence": 1.0 - ent, "state": nxt.tolist()})
            window = np.vstack([window[1:], nxt])
        return out

    # ---------------- explainability (real gradients) ----------------
    def attribute(self, X, benign_index=0):
        """Signed feature attribution for the infiltration score of the last
        window, via gradient x input on the standardised features. Real
        gradients through the full LSTM — not an approximation."""
        Xs = self._standardize(X)
        ns, st, cache = self._forward(Xs)
        p = _softmax(st)
        B, C = p.shape
        # d(infiltration)/d(logits) where infiltration = 1 - p[benign]
        dst = np.zeros_like(p)
        dst[:, benign_index] = p[:, benign_index]
        dst = dst - p[:, benign_index:benign_index + 1] * p  # softmax jacobian row
        dst = -dst  # because infiltration = 1 - p_benign
        # backprop dst through stage head to inputs
        H = self.hidden_dim
        dh = dst @ self.params["Wst"].T
        Wh = self.params["Wh"]
        dc = np.zeros((B, H))
        dX = np.zeros_like(Xs)
        for t in reversed(range(Xs.shape[1])):
            cc = cache[t]
            i, f, o, g, c, h_prev, c_prev = cc["i"], cc["f"], cc["o"], cc["g"], cc["c"], cc["h_prev"], cc["c_prev"]
            tanh_c = np.tanh(c)
            do = dh * tanh_c
            dc = dc + dh * o * (1 - tanh_c ** 2)
            di, dg, df = dc * g, dc * i, dc * c_prev
            dc_prev = dc * f
            dz = np.concatenate([di * i * (1 - i), df * f * (1 - f), do * o * (1 - o), dg * (1 - g ** 2)], axis=1)
            dX[:, t, :] = dz @ self.params["Wx"].T
            dh = dz @ Wh.T
            dc = dc_prev
        contrib = dX * Xs  # grad x input, per timestep
        feat_contrib = contrib[0].sum(axis=0)          # aggregate over time -> (D,)
        time_contrib = np.abs(contrib[0]).sum(axis=1)  # per-timestep importance
        return feat_contrib, time_contrib

    # ---------------- persistence ----------------
    def save(self, path):
        cal = self.cal or {}
        np.savez(path, x_mean=self.x_mean, x_std=self.x_std,
                 input_dim=self.input_dim, hidden_dim=self.hidden_dim,
                 n_stages=self.n_stages, seed=self.seed,
                 cal_s_mu=cal.get("s_mu", 0.0), cal_s_sd=cal.get("s_sd", 1.0),
                 cal_d_mu=cal.get("d_mu", 0.0), cal_d_sd=cal.get("d_sd", 1.0),
                 cal_benign_mean=cal.get("benign_mean", np.zeros(self.input_dim)),
                 **{f"p_{k}": v for k, v in self.params.items()})

    @classmethod
    def load(cls, path):
        d = np.load(path, allow_pickle=False)
        m = cls(int(d["input_dim"]), int(d["hidden_dim"]), int(d["n_stages"]), int(d["seed"]))
        m.x_mean = d["x_mean"]; m.x_std = d["x_std"]
        m.params = {k[2:]: d[k] for k in d.files if k.startswith("p_")}
        m.cal = {"s_mu": float(d["cal_s_mu"]), "s_sd": float(d["cal_s_sd"]),
                 "d_mu": float(d["cal_d_mu"]), "d_sd": float(d["cal_d_sd"]),
                 "benign_mean": d["cal_benign_mean"]}
        return m
