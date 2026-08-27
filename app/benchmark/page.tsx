"use client";

import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { ConfusionMatrix, RocCurve, LineChart, Panel, COLORS } from "@/components/charts";

const METRICS: { key: "precision" | "recall" | "f1" | "rocAuc" | "prAuc" | "fpr"; label: string; invert?: boolean }[] = [
  { key: "f1", label: "F1 Score" },
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "rocAuc", label: "ROC-AUC" },
  { key: "prAuc", label: "PR-AUC" },
  { key: "fpr", label: "False Positive Rate", invert: true },
];

export default function BenchmarkPage() {
  const { result } = useStore();
  if (!result) return (<><Topbar title="Benchmark" sub="World model vs conventional classifier" /><NeedData /></>);
  const b = result.benchmark;

  return (
    <>
      <Topbar title="Benchmark" sub="Sentinel world model vs logistic-regression IDS baseline · chronological hold-out" />

      {!b.hasLabels && (
        <div className="badge b-elev" style={{ marginBottom: 16 }}><span className="dot" />
          Unlabelled capture — metrics require ground-truth labels. Load a labelled dataset (or the demo) for the full benchmark.
        </div>
      )}

      <div className="grid cols-4">
        <Hero label="Forecast lead time" value={`+${b.leadSeconds}s`} sub={`${b.leadWindows} windows earlier`} color={COLORS.ok} />
        <Hero label="World-model F1" value={b.world.f1.toFixed(2)} sub="unseen-stage hold-out" color={COLORS.brand} />
        <Hero label="Baseline F1" value={b.baseline.f1.toFixed(2)} sub="logistic regression" color={COLORS.muted} />
        <Hero label="Recall uplift" value={`${((b.world.recall - b.baseline.recall) * 100).toFixed(0)}pp`} sub="attacks caught vs missed" color={COLORS.high} />
      </div>

      <div className="section-title">Metric Comparison</div>
      <div className="card">
        {METRICS.map((m) => {
          const w = b.world[m.key], l = b.baseline[m.key];
          const wBetter = m.invert ? w <= l : w >= l;
          return (
            <div key={m.key} style={{ marginBottom: 14 }}>
              <div className="flex between" style={{ fontSize: 12.5, marginBottom: 5 }}>
                <span className="muted">{m.label}{m.invert ? " (lower is better)" : ""}</span>
                <span className="mono"><span style={{ color: COLORS.brand }}>{w.toFixed(3)}</span> <span className="faint">vs</span> <span style={{ color: COLORS.muted }}>{l.toFixed(3)}</span></span>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <div className="bar-track" style={{ flex: 1 }}><div className="bar-fill" style={{ width: `${w * 100}%`, background: COLORS.brand }} /></div>
                <div className="bar-track" style={{ flex: 1 }}><div className="bar-fill" style={{ width: `${l * 100}%`, background: "#3b4048" }} /></div>
              </div>
            </div>
          );
        })}
        <div className="legend" style={{ marginTop: 4 }}>
          <span><i style={{ background: COLORS.brand }} />Sentinel world model</span>
          <span><i style={{ background: "#3b4048" }} />Logistic-regression baseline</span>
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <Panel title="ROC — World Model vs Baseline">
          <div style={{ display: "grid", placeItems: "center" }}>
            <RocCurve curves={[
              { label: "World model", color: COLORS.brand, scores: b.wmScores, labels: b.testLabels },
              { label: "Baseline", color: "#f59e0b", scores: b.blScores, labels: b.testLabels },
            ]} />
          </div>
          <div className="legend" style={{ justifyContent: "center" }}>
            <span><i style={{ background: COLORS.brand }} />WM (AUC {b.world.rocAuc.toFixed(2)})</span>
            <span><i style={{ background: "#f59e0b" }} />Baseline (AUC {b.baseline.rocAuc.toFixed(2)})</span>
          </div>
        </Panel>

        <Panel title="Predictive Score Over Hold-out Windows">
          <LineChart height={220}
            series={[
              { label: "World model", color: COLORS.brand, points: b.wmScores },
              { label: "Baseline", color: "#f59e0b", points: b.blScores, dashed: true },
            ]}
            markers={b.onsetIndex >= 0 ? [{ x: b.onsetIndex, label: "attack onset", color: COLORS.high }] : []} />
          <div className="legend" style={{ marginTop: 6 }}>
            <span><i style={{ background: COLORS.brand }} />World model (forecast max)</span>
            <span><i style={{ background: "#f59e0b" }} />Baseline (per-window)</span>
            <span className="faint">The baseline collapses on unseen later-stage attacks the world model still forecasts.</span>
          </div>
        </Panel>
      </div>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <Panel title="World Model — Confusion Matrix"><ConfusionMatrix {...b.world} title="test split" /></Panel>
        <Panel title="Baseline — Confusion Matrix"><ConfusionMatrix {...b.baseline} title="test split" /></Panel>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Methodology</h3>
        <p className="muted" style={{ fontSize: 13, marginTop: 8 }}>
          Windows are split chronologically (first 60% train / last 40% test) so later attack stages appear only in the test
          set — an unseen-stage generalisation test, not a random shuffle. Both models are fit on the training split only;
          decision thresholds are chosen at a fixed 5% false-positive rate on training predictions (never tuned on the test
          set). Lead time is measured over the full timeline as the extra windows the world model sustains its alarm before
          the baseline, leading into the final attack stage. All metrics are computed from this evaluation — none are hardcoded.
        </p>
      </div>
    </>
  );
}

function Hero({ label, value, sub, color }: { label: string; value: string; sub: string; color: string }) {
  return (
    <div className="card"><div className="stat">
      <span className="tag">{label}</span>
      <div className="val" style={{ color }}>{value}</div>
      <div className="sub">{sub}</div>
    </div></div>
  );
}
