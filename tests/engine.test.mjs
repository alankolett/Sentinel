// Engine unit tests. Run with: npm test  (Node >= 22 strips TS types natively)
import { test } from "node:test";
import assert from "node:assert/strict";
import { demoFlows, demoCsv } from "../lib/demo.ts";
import { parseCsv, detectSchema, splitCsvLine, isAttackLabel } from "../lib/parse.ts";
import { buildWindows } from "../lib/features.ts";
import { fitWorldModel, forecast, kmeans, fitTransition } from "../lib/worldModel.ts";
import { trainLogReg, predictLogReg, rocAuc, prAuc, metricsAt } from "../lib/baseline.ts";
import { analyze } from "../lib/analyze.ts";

test("csv splitter handles quotes and commas", () => {
  assert.deepEqual(splitCsvLine('a,"b,c",d'), ["a", "b,c", "d"]);
});

test("schema detection matches CIC-style headers", () => {
  const s = detectSchema(["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Label"]);
  assert.ok(s.matched >= 6);
  assert.equal(s.mapping.srcIp >= 0, true);
});

test("isAttackLabel distinguishes benign", () => {
  assert.equal(isAttackLabel("BENIGN"), false);
  assert.equal(isAttackLabel("PortScan"), true);
  assert.equal(isAttackLabel(undefined), false);
});

test("demo csv round-trips through parser", () => {
  const csv = demoCsv(7);
  const { flows, schema } = parseCsv(csv);
  assert.ok(flows.length > 500);
  assert.ok(schema.matched >= 10);
  assert.ok(flows.some((f) => f.label === "Exfiltration"));
});

test("kmeans is deterministic under a seed", () => {
  const data = Array.from({ length: 60 }, (_, i) => [Math.sin(i), Math.cos(i), i % 3]);
  const a = kmeans(data, 4, 42);
  const b = kmeans(data, 4, 42);
  assert.deepEqual(a.assign, b.assign);
});

test("transition matrix rows are stochastic", () => {
  const T = fitTransition([0, 1, 2, 1, 0, 2, 2, 1], 3);
  for (const row of T) {
    const s = row.reduce((x, y) => x + y, 0);
    assert.ok(Math.abs(s - 1) < 1e-9);
  }
});

test("world model forecast returns K+1 steps with valid probabilities", () => {
  const windows = buildWindows(demoFlows(7));
  const wm = fitWorldModel(windows, { seed: 42 });
  const fc = forecast(windows[windows.length - 1].vec, wm, 5);
  assert.equal(fc.length, 6);
  for (const s of fc) {
    assert.ok(s.infiltration >= 0 && s.infiltration <= 1);
    assert.ok(s.confidence >= 0 && s.confidence <= 1);
    assert.ok(Math.abs(s.dist.reduce((a, b) => a + b, 0) - 1) < 1e-6);
  }
});

test("rocAuc/prAuc bounded and sensible", () => {
  const scores = [0.1, 0.4, 0.35, 0.8, 0.7, 0.2];
  const labels = [0, 0, 0, 1, 1, 0];
  const auc = rocAuc(scores, labels);
  assert.ok(auc >= 0 && auc <= 1);
  assert.ok(auc > 0.5);
  assert.ok(prAuc(scores, labels) > 0);
});

test("logistic regression learns separable data", () => {
  const vecs = [], y = [];
  for (let i = 0; i < 40; i++) { vecs.push(new Array(18).fill(0).map((_, j) => (j === 0 ? -2 : 0))); y.push(0); }
  for (let i = 0; i < 40; i++) { vecs.push(new Array(18).fill(0).map((_, j) => (j === 0 ? 2 : 0))); y.push(1); }
  const m = trainLogReg(vecs, y, { epochs: 300 });
  assert.ok(predictLogReg(m, vecs[0]) < 0.3);
  assert.ok(predictLogReg(m, vecs[79]) > 0.7);
});

test("full analyze pipeline on labelled demo capture", () => {
  const res = analyze(demoFlows(7), { K: 5 });
  assert.ok(res.windows.length >= 8);
  assert.ok(res.forecast.length === 6);
  assert.ok(res.attributions.length === 18);
  assert.equal(res.meta.datasetLabelled, true);
  // benchmark must produce real metrics
  assert.ok(res.benchmark.world.f1 >= 0 && res.benchmark.world.f1 <= 1);
  assert.ok(res.benchmark.baseline.f1 >= 0 && res.benchmark.baseline.f1 <= 1);
  assert.ok(res.graph.nodes.length > 0);
});

test("metricsAt confusion counts are consistent", () => {
  const m = metricsAt([0.9, 0.8, 0.2, 0.1], [1, 0, 1, 0], 0.5);
  assert.equal(m.tp + m.fp + m.tn + m.fn, 4);
});

// ---- robustness: engine must never crash on pathological uploads ----
import { analyze as analyze2 } from "../lib/analyze.ts";
import { demoFlows as demo2 } from "../lib/demo.ts";

test("rejects unknown schema with a clear error", () => {
  assert.throws(() => parseCsv("colA,colB\n1,2\n3,4"), /Unrecognised schema|schema/i);
});

test("rejects a too-short capture without throwing raw", () => {
  const flows = demo2(7).slice(0, 6);
  assert.throws(() => analyze2(flows, { K: 5 }), /window/i);
});

test("all-benign capture analyses without labels and does not crash", () => {
  const flows = demo2(7).map((f) => ({ ...f, label: "BENIGN" }));
  const res = analyze2(flows, { K: 5 });
  assert.equal(res.meta.datasetLabelled, false);
  assert.ok(res.forecast.length === 6);
  assert.ok(res.benchmark.world.f1 >= 0);
});

test("degenerate single-host constant traffic does not crash", () => {
  const base = demo2(7)[0];
  const flows = Array.from({ length: 300 }, (_, i) => ({ ...base, ts: base.ts + i * 1000, srcIp: "10.0.0.5", dstIp: "10.0.0.9", dstPort: 443, label: "BENIGN" }));
  const res = analyze2(flows, { K: 4 });
  assert.ok(Number.isFinite(res.currentInfiltration));
  assert.ok(res.forecast.every((s) => Number.isFinite(s.infiltration)));
});

test("malformed rows are skipped, valid ones parsed", () => {
  const csv = "Src IP,Dst IP,Src Port,Dst Port,Protocol,Label\n10.0.0.1,10.0.0.2,1,80,TCP,BENIGN\n,,,\n10.0.0.1,10.0.0.3,2,443,TCP,PortScan";
  const { flows } = parseCsv(csv);
  assert.ok(flows.length >= 2);
});
