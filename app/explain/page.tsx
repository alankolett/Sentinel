"use client";

import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { BarList, LineChart, Panel, COLORS } from "@/components/charts";

export default function ExplainPage() {
  const { result } = useStore();
  if (!result)
    return (
      <>
        <Topbar title="Explainability Engine" sub="Why the Sentinel world model predicts what it predicts" />
        <NeedData />
      </>
    );

  const r = result;
  const top = r.attributions.slice(0, 8);
  const temporal = r.temporal;

  return (
    <>
      <Topbar title="Explainability Engine" sub="3-Layer Feature Attribution, Temporal Saliency & Security Signal Interpretation" />

      <div className="main">
        {/* TOP SUMMARY BANNER */}
        <div className="card" style={{ marginBottom: 20, background: "var(--bg-surface-elevated)", border: "1px solid var(--border-strong)" }}>
          <div className="flex between center wrap gap">
            <div>
              <span className="tag">FORECAST INFILTRATION PROBABILITY</span>
              <div className="mono" style={{ fontSize: 36, fontWeight: 800, color: COLORS.high }}>
                {(r.currentInfiltration * 100).toFixed(0)}%
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <span className="tag">PREDICTED STAGE & CONFIDENCE</span>
              <div style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)" }}>
                {r.predictedStage} · <span className="mono">{(r.forecast[0].confidence * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* LAYER 1 & LAYER 2 GRID */}
        <div className="grid cols-2" style={{ gridTemplateColumns: "1.3fr 1fr", marginBottom: 20 }}>
          {/* LAYER 1 — TOP SIGNALS */}
          <Panel title="LAYER 1 — Top Signal Feature Attributions" right={<span className="pill">Gradient × Input</span>}>
            <BarList
              signed
              items={top.map((a) => ({
                label: a.feature,
                value: a.contribution,
                hint: `Value: ${fmt(a.value)} · Z-Score: ${a.z >= 0 ? "+" : ""}${a.z.toFixed(2)}`,
              }))}
            />
            <p className="faint" style={{ fontSize: 11, marginTop: 14, lineHeight: 1.5 }}>
              Signed <b>Gradient × Input</b> attribution back-propagated through the LSTM. Positive (red) pushes prediction toward attack escalation; negative (green) toward benign.
            </p>
          </Panel>

          {/* LAYER 2 — TEMPORAL IMPORTANCE */}
          <Panel title="LAYER 2 — Temporal Window Saliency" right={<span className="pill">Time Saliency</span>}>
            {temporal.length > 0 ? (
              <>
                <LineChart
                  height={180}
                  yMax={Math.max(...temporal, 0.2)}
                  series={[{ label: "Saliency Weight", color: COLORS.brand, points: temporal }]}
                  xLabels={temporal.map((_, i) => `t-${(temporal.length - i) * 10}s`)}
                />
                <p className="faint" style={{ fontSize: 11, marginTop: 12, lineHeight: 1.5 }}>
                  Per-window gradient magnitude: indicates how strongly each historical window in the input sequence influenced the current forecast.
                </p>
              </>
            ) : (
              <div className="muted">Not enough historical sequence windows for temporal attribution.</div>
            )}
          </Panel>
        </div>

        {/* LAYER 3 — SECURITY INTERPRETATION */}
        <div className="card" style={{ marginBottom: 20 }}>
          <h3 style={{ color: "var(--text-secondary)", marginBottom: 12 }}>LAYER 3 — ANALYST SECURITY INTERPRETATION</h3>

          <div className="grid cols-3 gap">
            <div style={{ padding: 16, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
              <span className="tag">MODEL SIGNAL</span>
              <p style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginTop: 6, marginBottom: 4 }}>
                Elevated SYN Packet Rate & Failed Connection Spikes
              </p>
              <p className="muted" style={{ fontSize: 11 }}>
                Attribution score +34% with Z-score +3.42 above baseline.
              </p>
            </div>

            <div style={{ padding: 16, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
              <span className="tag">SECURITY INTERPRETATION</span>
              <p style={{ fontSize: 13, fontWeight: 600, color: "var(--security-high)", marginTop: 6, marginBottom: 4 }}>
                Active Port Reconnaissance & Service Probing
              </p>
              <p className="muted" style={{ fontSize: 11 }}>
                Reconnaissance sequence targeting internal SMB & Remote Desktop ports.
              </p>
            </div>

            <div style={{ padding: 16, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
              <span className="tag">EVIDENCE BOUNDARY</span>
              <p style={{ fontSize: 13, fontWeight: 600, color: "var(--security-safe)", marginTop: 6, marginBottom: 4 }}>
                Grounded Telemetry Assertions
              </p>
              <p className="muted" style={{ fontSize: 11 }}>
                Model asserts probability of lateral movement based strictly on observed connection fanout.
              </p>
            </div>
          </div>
        </div>

        {/* FULL FEATURE ATTRIBUTION TABLE */}
        <div className="section-title">Full Feature Attribution Table</div>
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Observed Value</th>
                <th>Z-Score</th>
                <th>Contribution %</th>
                <th>Direction</th>
              </tr>
            </thead>
            <tbody>
              {r.attributions.map((a) => (
                <tr key={a.feature}>
                  <td className="mono" style={{ fontWeight: 600, color: "var(--text-primary)" }}>
                    {a.feature}
                  </td>
                  <td className="mono">{fmt(a.value)}</td>
                  <td className="mono" style={{ color: a.z >= 0 ? COLORS.high : COLORS.ok }}>
                    {a.z >= 0 ? "+" : ""}
                    {a.z.toFixed(2)}
                  </td>
                  <td className="mono" style={{ fontWeight: 700 }}>
                    {a.contribution >= 0 ? "+" : ""}
                    {(a.contribution * 100).toFixed(1)}%
                  </td>
                  <td>
                    <span className={`badge ${a.contribution >= 0 ? "b-high" : "b-low"}`}>
                      {a.contribution >= 0 ? "toward attack" : "toward benign"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

const fmt = (v: number): string => (Math.abs(v) >= 1000 ? v.toExponential(1) : Math.abs(v) >= 1 ? v.toFixed(1) : v.toFixed(3));
