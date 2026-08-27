# Sentinel — 2-Minute Demo Shot List

Every shot below is something the running app actually produces (offline, real
inference). Start with `./run.sh` (or `docker compose up`) and open
**http://localhost:3000**.

| # | Time | Shot | On screen | Voiceover |
|---|------|------|-----------|-----------|
| 1 | 0:00–0:12 | **Dashboard** — click **Run demo capture** (real model) | Masthead "Threat Operations"; THREAT LEVEL **Critical**; CURRENT STAGE **Initial Access**; gauge ~72–98%; badge "Synthetic infiltration capture · CIC-IDS2018-trained model" | "Sentinel is a network world model — it forecasts where an intrusion is heading, not just whether a packet is bad." |
| 2 | 0:12–0:30 | **K-step forecast** panel | Infiltration curve rolled forward `P(Sₜ₊ₖ)` | "Instead of classifying one flow, it learns how the network *state* evolves and rolls the dynamics forward five steps." |
| 3 | 0:30–0:48 | **Upload & Analyze** → drop a real **CIC-IDS2018** slice (or UNSW/CTU CSV / PCAP) | Loading → real server-side inference runs | "Drop a real flow capture — CIC-IDS2018, UNSW-NB15, CTU-13, or a PCAP. It's parsed, windowed into network states, and run through the trained model server-side." |
| 4 | 0:48–1:04 | **Attack Forecast** page | Observed→forecast infiltration timeline; predicted **ATT&CK stage** trajectory cards | "Here's the trajectory — current stage, predicted next stage, and the infiltration probability climbing before compromise completes." |
| 5 | 1:04–1:20 | **Explainability** page | Signed feature attribution (grad×input) + temporal weights | "Every prediction is interpretable — real gradients through the model point at the driving features: failed connections, port-scan breadth, lateral fan-out." |
| 6 | 1:20–1:34 | **Network Graph** | Attacker node red at centre, dashed suspicious edges | "The host graph highlights the suspicious source and the predicted lateral-movement paths." |
| 7 | 1:34–1:56 | **Benchmark** page | Table: **F1 0.664 vs 0.230**, **recall 0.606 vs 0.135**, **+20 s lead**; ROC curve | "Against a logistic-regression IDS on a real CIC-IDS2018 chronological split, at the same 5% false-alarm budget, the world model catches 61% of infiltration windows versus the classifier's 14% — a 4.5× recall gain — and alarms 20 seconds earlier." |
| 8 | 1:56–2:00 | Terminal | `python train.py` → real numbers reprint | "And it's reproducible from a real public dataset — the numbers on screen equal a fresh run. Nothing is hardcoded." |

**Contrast line to land:** *"Traditional IDS says 'attack detected.' Sentinel says 'attack predicted — before the infiltration completes.'"*
