// The world model: learns latent network states and their transition dynamics
// P(S_{t+1} | S_t), then rolls the dynamics forward K steps to forecast the
// infiltration-probability trajectory. This is genuine learned dynamics, not a
// static per-flow classifier — the differentiator required by SIH26153.

import type { WindowState, ClusterModel, TransitionModel, ForecastStep, Stage } from "./types.ts";
import { FEATURES } from "./types.ts";
import { mapClusterStage, clusterInfiltrationSignature } from "./attack.ts";

// ---- deterministic PRNG (mulberry32) so training is fully reproducible ----
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface Standardizer { mean: number[]; std: number[]; }

export function fitStandardizer(vecs: number[][]): Standardizer {
  const d = FEATURES.length;
  const mean = new Array(d).fill(0);
  const std = new Array(d).fill(0);
  for (const v of vecs) for (let j = 0; j < d; j++) mean[j] += v[j];
  for (let j = 0; j < d; j++) mean[j] /= vecs.length || 1;
  for (const v of vecs) for (let j = 0; j < d; j++) std[j] += (v[j] - mean[j]) ** 2;
  for (let j = 0; j < d; j++) std[j] = Math.sqrt(std[j] / (vecs.length || 1)) || 1;
  return { mean, std };
}

export const zscore = (v: number[], s: Standardizer): number[] =>
  v.map((x, j) => (x - s.mean[j]) / s.std[j]);

const dist2 = (a: number[], b: number[]): number => {
  let s = 0;
  for (let j = 0; j < a.length; j++) s += (a[j] - b[j]) ** 2;
  return s;
};

/** k-means (Lloyd) with k-means++ init, deterministic under a fixed seed. */
export function kmeans(data: number[][], k: number, seed = 42, iters = 50): { centroids: number[][]; assign: number[] } {
  const n = data.length;
  if (n === 0) return { centroids: [], assign: [] };
  k = Math.max(1, Math.min(k, n)); // never request more clusters than points
  const r = rng(seed);
  const centroids: number[][] = [data[Math.floor(r() * n)].slice()];
  while (centroids.length < k) {
    const d2 = data.map((p) => Math.min(...centroids.map((c) => dist2(p, c))));
    const sum = d2.reduce((a, b) => a + b, 0) || 1;
    let target = r() * sum;
    let idx = 0;
    for (let i = 0; i < n; i++) { target -= d2[i]; if (target <= 0) { idx = i; break; } }
    centroids.push(data[idx].slice());
  }
  const assign = new Array(n).fill(0);
  for (let it = 0; it < iters; it++) {
    let moved = false;
    for (let i = 0; i < n; i++) {
      let best = 0, bd = Infinity;
      for (let c = 0; c < k; c++) { const d = dist2(data[i], centroids[c]); if (d < bd) { bd = d; best = c; } }
      if (assign[i] !== best) { assign[i] = best; moved = true; }
    }
    const sums = centroids.map(() => new Array(data[0].length).fill(0));
    const counts = new Array(k).fill(0);
    for (let i = 0; i < n; i++) { counts[assign[i]]++; const s = sums[assign[i]]; for (let j = 0; j < s.length; j++) s[j] += data[i][j]; }
    for (let c = 0; c < k; c++) if (counts[c] > 0) for (let j = 0; j < centroids[c].length; j++) centroids[c][j] = sums[c][j] / counts[c];
    if (!moved && it > 0) break;
  }
  return { centroids, assign };
}

export interface WorldModel {
  std: Standardizer;
  cluster: ClusterModel;
  transition: TransitionModel;
  assign: number[]; // cluster per training window
}

/** Fit the full world model from a chronological sequence of window states. */
export function fitWorldModel(windows: WindowState[], opts: { k?: number; seed?: number } = {}): WorldModel {
  const seed = opts.seed ?? 42;
  const vecs = windows.map((w) => w.vec);
  const std = fitStandardizer(vecs);
  const z = vecs.map((v) => zscore(v, std));
  const kReq = Math.max(3, Math.min(opts.k ?? 7, Math.max(3, Math.floor(windows.length / 3))));
  const { centroids, assign } = kmeans(z, kReq, seed);
  const k = centroids.length; // kmeans may clamp k to the number of points

  // Per-cluster infiltration score: blend of (a) supervised malicious rate if
  // labels exist and (b) an unsupervised behavioural risk from the centroid
  // signature. Both are real, data-derived quantities.
  const sizes = new Array(k).fill(0);
  const malCount = new Array(k).fill(0);
  for (let i = 0; i < assign.length; i++) { sizes[assign[i]]++; if (windows[i].malicious) malCount[assign[i]]++; }
  const hasLabels = windows.some((w) => w.malicious);
  const infiltration = new Array(k).fill(0);
  const stage: Stage[] = new Array(k).fill("Benign");
  for (let c = 0; c < k; c++) {
    const sig = clusterInfiltrationSignature(centroids[c], std);
    const supervised = sizes[c] > 0 ? malCount[c] / sizes[c] : 0;
    infiltration[c] = hasLabels ? 0.6 * supervised + 0.4 * sig.risk : sig.risk;
    stage[c] = mapClusterStage(sig, infiltration[c]);
  }

  const T = fitTransition(assign, k, seed);
  return { std, cluster: { k, centroids, mean: std.mean, std: std.std, infiltration, stage, sizes }, transition: { T }, assign };
}

/** Count transitions with Laplace(1) smoothing → row-stochastic matrix. */
export function fitTransition(seq: number[], k: number, _seed = 42): number[][] {
  const T = Array.from({ length: k }, () => new Array(k).fill(1)); // Laplace prior
  for (let i = 1; i < seq.length; i++) T[seq[i - 1]][seq[i]]++;
  return T.map((row) => { const s = row.reduce((a, b) => a + b, 0); return row.map((x) => x / s); });
}

/** Assign a single window vector to its nearest latent state. */
export function assignState(vec: number[], m: WorldModel): number {
  const z = zscore(vec, m.std);
  let best = 0, bd = Infinity;
  for (let c = 0; c < m.cluster.k; c++) { const d = dist2(z, m.cluster.centroids[c]); if (d < bd) { bd = d; best = c; } }
  return best;
}

const entropy = (p: number[]): number => {
  let h = 0;
  for (const x of p) if (x > 0) h -= x * Math.log(x);
  return h / Math.log(p.length); // normalised 0..1
};

const matVec = (T: number[][], p: number[]): number[] =>
  T[0].map((_, j) => p.reduce((s, pi, i) => s + pi * T[i][j], 0));

/**
 * K-step forward simulation. Starts from a soft state distribution around the
 * current window and repeatedly applies the transition matrix, reporting the
 * expected infiltration probability and most-likely stage at each horizon.
 */
export function forecast(currentVec: number[], m: WorldModel, K: number): ForecastStep[] {
  const k = m.cluster.k;
  const z = zscore(currentVec, m.std);
  // Soft assignment via inverse-distance so uncertainty is honest.
  const d = m.cluster.centroids.map((c) => Math.sqrt(dist2(z, c)) + 1e-6);
  const inv = d.map((x) => 1 / (x * x));
  const s = inv.reduce((a, b) => a + b, 0);
  let p = inv.map((x) => x / s);
  const out: ForecastStep[] = [];
  for (let step = 0; step <= K; step++) {
    const infil = p.reduce((acc, pi, i) => acc + pi * m.cluster.infiltration[i], 0);
    // dominant stage weighted by probability mass
    const stageWeight = new Map<Stage, number>();
    for (let i = 0; i < k; i++) stageWeight.set(m.cluster.stage[i], (stageWeight.get(m.cluster.stage[i]) ?? 0) + p[i]);
    let topStage: Stage = "Benign", tw = -1;
    for (const [st, w] of stageWeight) if (w > tw) { tw = w; topStage = st; }
    out.push({ step, dist: p.slice(), infiltration: clamp01(infil), topStage, confidence: 1 - entropy(p) });
    p = matVec(m.transition.T, p);
  }
  return out;
}

const clamp01 = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);

/** Stationary distribution (power iteration) — used for network baseline stats. */
export function stationary(T: number[][], iters = 200): number[] {
  let p = new Array(T.length).fill(1 / T.length);
  for (let i = 0; i < iters; i++) p = matVec(T, p);
  return p;
}
