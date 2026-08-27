# Sentinel — 5-Slide Technical Presentation

## Slide 1 — Problem & existing gap
- SIH 26153 (NTRO): **AI network attack forecasting from traffic data**.
- An infiltration is a *process over time* — recon → access → lateral → C2 → exfil.
- Conventional ML IDS classify each flow in isolation `P(attack|flow)`; they react on impact and **miss unseen attack stages**.
- CII/enterprise defenders need **prediction**, not post-hoc detection.

## Slide 2 — Solution & innovation (world model)
- Learn **transition dynamics `P(Sₜ₊₁|Sₜ,…)`** with a recurrent sequence model; roll K steps forward.
- **Detection = the trained LSTM temporal stage head** — `1 − P(benign | last 8 windows)` reads the *sequence* of network states, beating a single-window classifier (auxiliary unsupervised novelty channel also computed).
- Interpretable by construction (real gradients: feature + temporal attribution); evidence-based MITRE ATT&CK mapping.
- **"IDS: attack detected. Sentinel: attack predicted — before compromise."**

## Slide 3 — Technical architecture
```
Flow/PCAP → schema-adaptive feature pipeline → 18-d windowed state Sₜ
 → LSTM world model (BPTT+Adam; next-state + stage heads)
 → K-step rollout → infiltration curve + ATT&CK stage + attribution
 → FastAPI (offline, sandboxed uploads) → Next.js SOC dashboard
```
- Reproducible (seeded); fully **offline** (no cloud APIs); pinned deps, 0 vulns; subprocess-isolated parsing.

## Slide 4 — Results & comparison
**Real** CSE-CIC-IDS2018 (Infiltration day, 331k flows); chronological split
(train earlier / test later, no leakage); both at a fixed **5% false-positive budget**:

| | **Sentinel** | Logistic IDS |
|---|---|---|
| F1 @ 5% FPR | **0.664** | 0.230 |
| Recall @ 5% FPR | **0.606** | 0.135 |
| PR-AUC | **0.683** | 0.665 |
| ROC-AUC | 0.802 | 0.813 |
| Forecast lead | **+20 s** | — |

- Catches **61%** of infiltration windows vs **14%** at equal false-alarm budget (4.5× recall), alarming **2 windows earlier**. Ranking metrics ~tied; advantage is at the operating point.
- Honest, not perfect — `python train.py` reproduces every figure bit-for-bit from a real public dataset.

## Slide 5 — Impact, scalability & future scope
- **Impact:** shifts the SOC from detection to **anticipation** — earlier containment across enterprise & CII.
- **Scalability:** encoder-agnostic pipeline — drop in a Torch **Transformer** encoder and a **temporal GNN** over the host graph; streaming ingestion; per-tenant models.
- **Deployable now:** `docker compose up`, offline, dependency-light.
- **Future:** uncertainty calibration, auth-log/multi-modal fusion, adversarial-robustness hardening, automated response playbooks.
