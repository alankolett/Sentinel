// Conventional baseline: L2-regularised logistic regression trained with
// full-batch gradient descent on the same window feature vectors. Provides the
// apples-to-apples comparison required by the brief. Also hosts the shared
// evaluation-metrics helpers.

import type { Metrics } from "./types.ts";
import { FEATURES } from "./types.ts";
import type { Standardizer } from "./worldModel.ts";
import { fitStandardizer, zscore } from "./worldModel.ts";

export interface LogRegModel {
  w: number[];
  b: number;
  std: Standardizer;
}

const sigmoid = (x: number): number => 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, x))));

export function trainLogReg(
  vecs: number[][],
  y: number[],
  opts: { lr?: number; epochs?: number; l2?: number } = {}
): LogRegModel {
  const lr = opts.lr ?? 0.1;
  const epochs = opts.epochs ?? 400;
  const l2 = opts.l2 ?? 1e-3;
  const std = fitStandardizer(vecs);
  const X = vecs.map((v) => zscore(v, std));
  const d = FEATURES.length;
  const w = new Array(d).fill(0);
  let b = 0;
  const n = X.length || 1;
  for (let e = 0; e < epochs; e++) {
    const gw = new Array(d).fill(0);
    let gb = 0;
    for (let i = 0; i < X.length; i++) {
      const p = sigmoid(dot(w, X[i]) + b);
      const err = p - y[i];
      for (let j = 0; j < d; j++) gw[j] += err * X[i][j];
      gb += err;
    }
    for (let j = 0; j < d; j++) w[j] -= lr * (gw[j] / n + l2 * w[j]);
    b -= lr * (gb / n);
  }
  return { w, b, std };
}

const dot = (a: number[], b: number[]): number => a.reduce((s, x, i) => s + x * b[i], 0);

export function predictLogReg(m: LogRegModel, vec: number[]): number {
  return sigmoid(dot(m.w, zscore(vec, m.std)) + m.b);
}

/** Exact per-feature attribution for a linear model at a point (w_j * x_j). */
export function logRegAttribution(m: LogRegModel, vec: number[]): { feature: string; contribution: number }[] {
  const z = zscore(vec, m.std);
  const contrib = m.w.map((wj, j) => wj * z[j]);
  const total = contrib.reduce((a, c) => a + Math.abs(c), 0) || 1;
  return FEATURES.map((f, j) => ({ feature: f, contribution: contrib[j] / total }))
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
}

// ---------------- metrics ----------------

export function metricsAt(scores: number[], labels: number[], thr: number): Metrics {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (let i = 0; i < scores.length; i++) {
    const pred = scores[i] >= thr ? 1 : 0;
    if (pred === 1 && labels[i] === 1) tp++;
    else if (pred === 1 && labels[i] === 0) fp++;
    else if (pred === 0 && labels[i] === 0) tn++;
    else fn++;
  }
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const accuracy = (tp + tn) / (scores.length || 1);
  return { precision, recall, f1, fpr, accuracy, tp, fp, tn, fn, rocAuc: rocAuc(scores, labels), prAuc: prAuc(scores, labels) };
}

/** Choose the decision threshold that maximises F1 on the given scores. */
export function bestThreshold(scores: number[], labels: number[]): number {
  let best = 0.5, bf1 = -1;
  const cands = Array.from(new Set(scores)).sort((a, b) => a - b);
  for (const t of cands) {
    const m = metricsAt(scores, labels, t);
    if (m.f1 > bf1) { bf1 = m.f1; best = t; }
  }
  return best;
}

/**
 * Detection operating point: the smallest threshold whose false-positive rate on
 * the (benign) negatives does not exceed `fpr`. This transfers across
 * distribution shift far better than an F1-optimal cut tuned on one split.
 */
export function thresholdAtFpr(scores: number[], labels: number[], fpr = 0.05): number {
  const neg = scores.filter((_, i) => labels[i] === 0).sort((a, b) => a - b);
  if (neg.length === 0) return 0.5;
  const idx = Math.min(neg.length - 1, Math.ceil((1 - fpr) * neg.length));
  return neg[idx] + 1e-9;
}

export function rocAuc(scores: number[], labels: number[]): number {
  const pos = labels.filter((l) => l === 1).length;
  const neg = labels.length - pos;
  if (pos === 0 || neg === 0) return 0.5;
  // Mann–Whitney U via rank averaging (handles ties).
  const order = scores.map((s, i) => ({ s, y: labels[i] })).sort((a, b) => a.s - b.s);
  let rank = 1, i = 0, rankSumPos = 0;
  while (i < order.length) {
    let j = i;
    while (j < order.length && order[j].s === order[i].s) j++;
    const avgRank = (rank + (rank + (j - i) - 1)) / 2;
    for (let k = i; k < j; k++) if (order[k].y === 1) rankSumPos += avgRank;
    rank += j - i; i = j;
  }
  return (rankSumPos - (pos * (pos + 1)) / 2) / (pos * neg);
}

export function prAuc(scores: number[], labels: number[]): number {
  const order = scores.map((s, i) => ({ s, y: labels[i] })).sort((a, b) => b.s - a.s);
  const totalPos = labels.filter((l) => l === 1).length || 1;
  let tp = 0, fp = 0, prevRecall = 0, area = 0, prevPrec = 1;
  for (const o of order) {
    if (o.y === 1) tp++; else fp++;
    const recall = tp / totalPos;
    const precision = tp / (tp + fp);
    area += (recall - prevRecall) * (precision + prevPrec) / 2;
    prevRecall = recall; prevPrec = precision;
  }
  return area;
}
