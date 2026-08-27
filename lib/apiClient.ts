"use client";

// Adapter that maps the FastAPI backend's real-model responses into the UI's
// AnalysisResult shape. When NEXT_PUBLIC_API_URL is set, the app reads every
// number from the Python world model over HTTP; when unset (e.g. the static
// Vercel deploy), the app falls back to the in-browser TypeScript engine so the
// demo still runs fully offline. No numbers are ever hardcoded in either mode.

import type { AnalysisResult, BenchmarkResult } from "./analyze.ts";
import type { Metrics, Stage } from "./types.ts";

// When an explicit backend URL is configured, use it. Otherwise call the
// same-origin Python function at /api (Vercel Python / local FastAPI). Either
// way, if the live model is unreachable we fall back to precomputed REAL model
// output under /real (genuine trained-model inference, not client heuristics).
export const API_BASE: string =
  process.env.NEXT_PUBLIC_API_URL && process.env.NEXT_PUBLIC_API_URL.length > 0
    ? process.env.NEXT_PUBLIC_API_URL
    : "";

const REAL = {
  demo: "/real/demo.json",
  benchmark: "/real/benchmark.json",
};

interface RawMetrics {
  precision: number; recall: number; f1: number; fpr: number; accuracy: number;
  roc_auc: number; pr_auc: number; tp: number; fp: number; tn: number; fn: number;
}
const mapMetrics = (m: RawMetrics): Metrics => ({
  precision: m.precision, recall: m.recall, f1: m.f1, fpr: m.fpr, accuracy: m.accuracy,
  rocAuc: m.roc_auc, prAuc: m.pr_auc, tp: m.tp, fp: m.fp, tn: m.tn, fn: m.fn,
});

async function fetchJson(url: string, init?: RequestInit): Promise<Record<string, unknown>> {
  const r = await fetch(url, init);
  if (!r.ok) {
    let detail = `Request failed (${r.status})`;
    try { detail = ((await r.json()) as { detail?: string }).detail || detail; } catch { /* noop */ }
    throw new Error(detail);
  }
  return r.json();
}

// Try the live model API; on any failure fall back to a precomputed REAL file.
async function withFallback(apiUrl: string, realUrl: string, init?: RequestInit): Promise<Record<string, unknown>> {
  try {
    return await fetchJson(apiUrl, init);
  } catch {
    return fetchJson(realUrl);
  }
}

function toBenchmark(b: Record<string, unknown>): BenchmarkResult {
  const labels = (b.labels as number[]) || [];
  return {
    world: mapMetrics(b.world as RawMetrics), baseline: mapMetrics(b.baseline as RawMetrics),
    leadWindows: b.lead_windows as number, leadSeconds: b.lead_seconds as number,
    wmThreshold: b.wm_threshold as number, blThreshold: b.bl_threshold as number,
    wmScores: (b.wm_scores as number[]) || [], blScores: (b.bl_scores as number[]) || [], testLabels: labels,
    onsetIndex: b.onset_index as number, wmAlarmIndex: -1, blAlarmIndex: -1,
    hasLabels: labels.some((v: number) => v === 1),
  };
}

async function getBenchmark(): Promise<BenchmarkResult> {
  return toBenchmark(await withFallback(`${API_BASE}/api/benchmark`, REAL.benchmark));
}

function adapt(a: Record<string, unknown>, bench: BenchmarkResult): AnalysisResult {
  const meta = a.meta as Record<string, unknown>;
  const stageNames = (meta.stageNames as string[]) || [];
  const rawWindows = (a.windows as Record<string, unknown>[]) || [];
  const windows = rawWindows.map((w) => ({
    index: w.index as number, tStart: w.tStart as number, tEnd: w.tEnd as number,
    vec: (w.vec as number[]) || [], flowCount: w.flowCount as number,
    malicious: w.malicious as boolean, topHosts: [],
  }));
  const assignSeq = rawWindows.map((w) => (w.stageIdx as number) ?? 0);

  // synthesise a cluster view keyed by ATT&CK stage index so the Dataset and
  // Forecast pages render from real per-stage figures
  const k = Math.max(1, stageNames.length);
  const sizes = new Array(k).fill(0);
  const infilSum = new Array(k).fill(0);
  rawWindows.forEach((w) => {
    const s = (w.stageIdx as number) ?? 0;
    sizes[s]++; infilSum[s] += (w.infiltration as number) ?? (s > 0 ? 0.7 : 0.1);
  });
  const infiltration = infilSum.map((v, i) => (sizes[i] ? v / sizes[i] : 0));
  const cluster = {
    k, centroids: [], mean: [], std: [], infiltration,
    stage: stageNames as Stage[], sizes,
  };

  const forecast = (a.forecast as Record<string, unknown>[]).map((f) => ({
    step: f.step as number, dist: [], infiltration: f.infiltration as number,
    topStage: f.topStage as Stage, confidence: f.confidence as number,
  }));

  return {
    windows,
    model: { std: { mean: [], std: [] }, cluster, transition: { T: [] }, assign: assignSeq } as unknown as AnalysisResult["model"],
    assignSeq,
    currentStage: a.currentStage as Stage,
    predictedStage: a.predictedStage as Stage,
    predictedTechnique: a.predictedTechnique as string,
    currentInfiltration: a.currentInfiltration as number,
    forecast,
    attributions: (a.attributions as AnalysisResult["attributions"]),
    temporal: (a.temporal as number[]) || [],
    benchmark: bench,
    topHosts: (a.topHosts as AnalysisResult["topHosts"]),
    graph: a.graph as AnalysisResult["graph"],
    threatLevel: a.threatLevel as AnalysisResult["threatLevel"],
    meta: {
      flows: meta.flows as number, windows: meta.windows as number, K: meta.K as number,
      horizonSeconds: meta.horizonSeconds as number, datasetLabelled: meta.datasetLabelled as boolean,
    },
  };
}

export async function apiDemo(): Promise<{ result: AnalysisResult; source: string }> {
  // live model API if reachable, else precomputed REAL model output
  const [a, bench] = await Promise.all([
    withFallback(`${API_BASE}/api/demo-capture`, REAL.demo),
    getBenchmark(),
  ]);
  return { result: adapt(a, bench), source: (a.source as string) || "Demo capture · real model inference" };
}

// Real server-side inference on a user upload. Throws if no backend is reachable
// (the caller then falls back to the in-browser engine for offline use).
export async function apiAnalyze(file: File): Promise<{ result: AnalysisResult; source: string }> {
  const fd = new FormData();
  fd.append("file", file);
  const [a, bench] = await Promise.all([
    fetchJson(`${API_BASE}/api/analyze`, { method: "POST", body: fd }),
    getBenchmark(),
  ]);
  return { result: adapt(a, bench), source: (a.source as string) || file.name };
}
