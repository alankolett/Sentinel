// Top-level orchestration: raw flows -> windows -> world model -> forecast ->
// explanation -> baseline benchmark. Produces a single AnalysisResult object
// that every dashboard page renders from. A temporal (chronological) train/test
// split is used for the benchmark to avoid leakage between adjacent windows.

import type { Flow, WindowState, ForecastStep, Attribution, Metrics, Stage, HostAgg } from "./types.ts";
import { buildWindows, DEFAULT_WINDOW } from "./features.ts";
import type { WindowOpts } from "./features.ts";
import { fitWorldModel, forecast, assignState } from "./worldModel.ts";
import type { WorldModel } from "./worldModel.ts";
import { explainForecast, temporalAttribution } from "./explain.ts";
import { trainLogReg, predictLogReg, metricsAt, thresholdAtFpr } from "./baseline.ts";
import { STAGE_TECHNIQUE } from "./attack.ts";

export interface BenchmarkResult {
  world: Metrics;
  baseline: Metrics;
  leadWindows: number;
  leadSeconds: number;
  wmThreshold: number;
  blThreshold: number;
  wmScores: number[]; // per test-window predictive infiltration
  blScores: number[];
  testLabels: number[];
  onsetIndex: number; // first malicious window in test split (-1 if none)
  wmAlarmIndex: number;
  blAlarmIndex: number;
  hasLabels: boolean;
}

export interface GraphNode { ip: string; suspicion: number; flows: number; internal: boolean; }
export interface GraphEdge { src: string; dst: string; weight: number; suspicious: boolean; }

export interface AnalysisResult {
  windows: WindowState[];
  model: WorldModel;
  assignSeq: number[];
  currentStage: Stage;
  predictedStage: Stage;
  predictedTechnique: string;
  currentInfiltration: number;
  forecast: ForecastStep[];
  attributions: Attribution[];
  temporal: number[];
  benchmark: BenchmarkResult;
  topHosts: HostAgg[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  threatLevel: "Low" | "Elevated" | "High" | "Critical";
  meta: { flows: number; windows: number; K: number; horizonSeconds: number; datasetLabelled: boolean };
}

const isPrivate = (ip: string): boolean =>
  /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip === "127.0.0.1";

export interface AnalyzeOpts { window?: WindowOpts; K?: number; k?: number; seed?: number; }

export function analyze(flows: Flow[], opts: AnalyzeOpts = {}): AnalysisResult {
  const win = opts.window ?? DEFAULT_WINDOW;
  const K = opts.K ?? 5;
  const windows = buildWindows(flows, win);
  if (windows.length < 4) throw new Error("Not enough temporal windows — provide a longer capture (need ≥ 4 windows).");

  // Display model fit on all windows for live forecast / graph.
  const model = fitWorldModel(windows, { k: opts.k, seed: opts.seed });
  const assignSeq = windows.map((w) => assignState(w.vec, model));

  // Current state = last window; predict forward.
  const current = windows[windows.length - 1];
  const fc = forecast(current.vec, model, K);
  const currentStage = model.cluster.stage[assignSeq[assignSeq.length - 1]];
  const future = fc.slice(1);
  const predictedStage = future.reduce((best, s) => (s.infiltration > best.infiltration ? s : best), fc[1] ?? fc[0]).topStage;
  const currentInfiltration = fc[0].infiltration;

  const attributions = explainForecast(current.vec, model);
  const temporal = temporalAttribution(assignSeq, model);

  const benchmark = runBenchmark(windows, win, K, opts);
  const graph = buildGraph(flows);
  const topHosts = mergeHosts(windows);

  const horizonSeconds = Math.round((K * win.strideMs) / 1000);
  const level = threat(Math.max(currentInfiltration, ...future.map((s) => s.infiltration)));

  return {
    windows, model, assignSeq, currentStage, predictedStage,
    predictedTechnique: STAGE_TECHNIQUE[predictedStage],
    currentInfiltration, forecast: fc, attributions, temporal, benchmark, topHosts, graph,
    threatLevel: level,
    meta: {
      flows: flows.length, windows: windows.length, K, horizonSeconds,
      datasetLabelled: windows.some((w) => w.malicious),
    },
  };
}

function threat(p: number): AnalysisResult["threatLevel"] {
  if (p >= 0.8) return "Critical";
  if (p >= 0.6) return "High";
  if (p >= 0.35) return "Elevated";
  return "Low";
}

function runBenchmark(windows: WindowState[], win: WindowOpts, K: number, opts: AnalyzeOpts): BenchmarkResult {
  const n = windows.length;
  const splitAt = Math.max(3, Math.floor(n * 0.6));
  const train = windows.slice(0, splitAt);
  const test = windows.slice(splitAt);
  const hasLabels = windows.some((w) => w.malicious);
  const y = (arr: WindowState[]): number[] => arr.map((w) => (w.malicious ? 1 : 0));

  // World model + baseline trained ONLY on the chronological training split;
  // the test split holds later attack stages the models never saw (unseen-stage
  // generalisation). Decision thresholds are chosen on TRAIN predictions to
  // avoid tuning on the evaluation data.
  const wm = fitWorldModel(train, { k: opts.k, seed: opts.seed });
  const bl = trainLogReg(train.map((w) => w.vec), y(train));

  // Predictive infiltration for a window = max forecast infiltration over horizon.
  const wmScore = (m: WorldModel) => (w: WindowState): number => {
    const f = forecast(w.vec, m, K);
    return Math.max(...f.slice(1).map((s) => s.infiltration), f[0].infiltration);
  };
  const wmTrain = train.map(wmScore(wm));
  const blTrain = train.map((w) => predictLogReg(bl, w.vec));
  const trainLabels = y(train);

  const wmScores = test.map(wmScore(wm));
  const blScores = test.map((w) => predictLogReg(bl, w.vec));
  const testLabels = y(test);

  let wmThr = 0.5, blThr = 0.5;
  if (hasLabels && trainLabels.some((v) => v === 1) && trainLabels.some((v) => v === 0)) {
    wmThr = thresholdAtFpr(wmTrain, trainLabels, 0.05);
    blThr = thresholdAtFpr(blTrain, trainLabels, 0.05);
  }
  const evalOk = testLabels.some((v) => v === 1) && testLabels.some((v) => v === 0);
  const world = metricsAt(wmScores, evalOk ? testLabels : testLabels.map(() => 0), wmThr);
  const baseline = metricsAt(blScores, evalOk ? testLabels : testLabels.map(() => 0), blThr);

  // Lead time is a mechanism demonstration measured over the FULL timeline using
  // the SAME train-fit models (no leakage): how many windows earlier does
  // forecasting (world model) raise a *sustained* alarm versus the static
  // classifier. The world model's forecast-max score rises as its learned
  // dynamics roll toward an attack state during the quiet gaps a static
  // classifier cannot see through.
  const fullWm = windows.map(wmScore(wm));
  const fullBl = windows.map((w) => predictLogReg(bl, w.vec));
  const onsetIndex = windows.findIndex((w) => w.malicious);
  const lastMal = windows.reduce((acc, w, i) => (w.malicious ? i : acc), -1);
  // Anchor at the final attack stage, then walk left over each model's
  // *contiguous* above-threshold run: how many windows earlier did the model
  // begin — and continuously sustain — the alarm that culminates in the attack?
  const runStart = (s: number[], thr: number, anchor: number): number => {
    if (anchor < 0) return anchor;
    let i = anchor;
    if (s[i] < thr) return anchor; // model isn't even flagging the attack itself
    while (i > 0 && s[i - 1] >= thr) i--;
    return i;
  };
  const wmAlarmIndex = runStart(fullWm, wmThr, lastMal);
  const blAlarmIndex = runStart(fullBl, blThr, lastMal);
  const leadWindows = wmAlarmIndex >= 0 && blAlarmIndex >= 0 ? Math.max(0, blAlarmIndex - wmAlarmIndex) : 0;
  const leadSeconds = Math.round((leadWindows * win.strideMs) / 1000);

  return {
    world, baseline, leadWindows, leadSeconds, wmThreshold: wmThr, blThreshold: blThr,
    wmScores, blScores, testLabels, onsetIndex, wmAlarmIndex, blAlarmIndex, hasLabels,
  };
}

function buildGraph(flows: Flow[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodeMap = new Map<string, { flows: number; syn: number; ack: number; ports: Set<number>; peers: Set<string> }>();
  const edgeMap = new Map<string, { w: number; syn: number; ack: number }>();
  const touch = (ip: string) => {
    let x = nodeMap.get(ip);
    if (!x) { x = { flows: 0, syn: 0, ack: 0, ports: new Set(), peers: new Set() }; nodeMap.set(ip, x); }
    return x;
  };
  for (const f of flows) {
    const s = touch(f.srcIp);
    touch(f.dstIp);
    s.flows++; s.syn += f.syn; s.ack += f.ack; s.ports.add(f.dstPort); s.peers.add(f.dstIp);
    const key = f.srcIp + " " + f.dstIp;
    let e = edgeMap.get(key);
    if (!e) { e = { w: 0, syn: 0, ack: 0 }; edgeMap.set(key, e); }
    e.w++; e.syn += f.syn; e.ack += f.ack;
  }
  const nodes: GraphNode[] = Array.from(nodeMap.entries()).map(([ip, x]) => {
    const scan = Math.min(1, x.ports.size / 30);
    const fanout = Math.min(1, x.peers.size / 15);
    const failed = x.syn > 0 ? Math.max(0, (x.syn - x.ack) / x.syn) : 0;
    return { ip, flows: x.flows, internal: isPrivate(ip), suspicion: Math.min(1, 0.45 * scan + 0.35 * fanout + 0.2 * failed) };
  });
  // keep the graph legible: top nodes by activity/suspicion
  nodes.sort((a, b) => b.suspicion - a.suspicion || b.flows - a.flows);
  const keep = new Set(nodes.slice(0, 40).map((n) => n.ip));
  const edges: GraphEdge[] = Array.from(edgeMap.entries())
    .map(([k, e]) => { const [src, dst] = k.split(" "); const failed = e.syn > 0 ? (e.syn - e.ack) / e.syn : 0; return { src, dst, weight: e.w, suspicious: failed > 0.5 || e.w > 20 }; })
    .filter((e) => keep.has(e.src) && keep.has(e.dst))
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 120);
  return { nodes: nodes.filter((n) => keep.has(n.ip)), edges };
}

function mergeHosts(windows: WindowState[]): HostAgg[] {
  const map = new Map<string, HostAgg>();
  for (const w of windows) for (const h of w.topHosts) {
    const e = map.get(h.ip);
    if (!e) map.set(h.ip, { ...h });
    else { e.flows += h.flows; e.bytes += h.bytes; e.dstPorts = Math.max(e.dstPorts, h.dstPorts); e.peers = Math.max(e.peers, h.peers); e.suspicion = Math.max(e.suspicion, h.suspicion); }
  }
  return Array.from(map.values()).sort((a, b) => b.suspicion - a.suspicion || b.flows - a.flows).slice(0, 10);
}
