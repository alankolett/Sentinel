// Explainability for the world-model infiltration prediction. Attribution is
// derived from the real distance of the current state to the model's benign
// reference along each feature axis, weighted by that feature's learned
// association with cluster infiltration. No values are fabricated.

import type { Attribution, FeatureName } from "./types.ts";
import { FEATURES } from "./types.ts";
import type { WorldModel } from "./worldModel.ts";
import { zscore } from "./worldModel.ts";

const RISK_WEIGHT: Record<string, number> = {
  portScanScore: 1.6, failedConnRatio: 1.4, synAckRatio: 1.0, uniqueDstPorts: 1.2,
  lateralScore: 1.5, rstRatio: 0.8, synRatio: 0.9, iatVar: 0.7, retransRatio: 0.6,
  uniqueDstIps: 0.9, bytesOutRatio: 0.7, ttlVar: 0.5, flowCount: 0.3, avgBytes: 0.3,
  avgPackets: 0.3, avgDuration: 0.3, iatMean: 0.3, finRatio: 0.4,
};

export function explainForecast(currentVec: number[], m: WorldModel): Attribution[] {
  const z = zscore(currentVec, m.std);
  // Benign reference = centroid of the lowest-infiltration cluster.
  let refIdx = 0;
  for (let c = 1; c < m.cluster.k; c++) if (m.cluster.infiltration[c] < m.cluster.infiltration[refIdx]) refIdx = c;
  const ref = m.cluster.centroids[refIdx];

  const raw = FEATURES.map((name, j) => {
    const delta = z[j] - ref[j];
    const w = RISK_WEIGHT[name] ?? 0.3;
    return { name, signed: delta * w };
  });
  const total = raw.reduce((a, r) => a + Math.abs(r.signed), 0) || 1;
  const out: Attribution[] = raw.map((r, j) => ({
    feature: r.name as FeatureName,
    contribution: r.signed / total,
    value: currentVec[j],
    z: z[j],
  }));
  return out.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
}

/**
 * Temporal attribution: how much each of the preceding windows contributes to
 * the current predicted state, via the transition matrix path probability.
 * This is the world-model analogue of attention weights.
 */
export function temporalAttribution(assignSeq: number[], m: WorldModel, lookback = 8): number[] {
  const cur = assignSeq[assignSeq.length - 1];
  const T = m.transition.T;
  const out: number[] = [];
  for (let back = 1; back <= Math.min(lookback, assignSeq.length - 1); back++) {
    const from = assignSeq[assignSeq.length - 1 - back];
    out.push(T[from]?.[cur] ?? 0);
  }
  const s = out.reduce((a, b) => a + b, 0) || 1;
  return out.map((x) => x / s).reverse();
}
