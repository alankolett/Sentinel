"use client";

import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { LineChart, Panel, COLORS } from "@/components/charts";
import { ForecastTimeline } from "@/components/ForecastTimeline";
import { STAGE_TECHNIQUE } from "@/lib/attack";

const stageColor = (s: string) =>
  s === "Benign"
    ? "var(--security-safe)"
    : /Exfil|Command|Lateral/.test(s)
    ? "var(--security-critical)"
    : /Access|Credential|Escalation/.test(s)
    ? "var(--security-high)"
    : "var(--security-warning)";

export default function ForecastPage() {
  const { result } = useStore();
  if (!result)
    return (
      <>
        <Topbar title="Attack Forecast Trajectory" sub="K-step forward simulation of network state transitions" />
        <NeedData />
      </>
    );

  const r = result;
  const hist = r.assignSeq.map((c) => r.model.cluster.infiltration[c]);
  const forecastTail = r.forecast.map((f) => f.infiltration);
  const combined = [...hist.slice(0, -1), ...forecastTail];
  const nowX = hist.length - 1;

  const BENIGN_T = 0.25;
  let lastAttack: string | null = r.currentStage !== "Benign" ? r.currentStage : null;
  let confFloor = Infinity;

  const steps = r.forecast.map((f) => {
    let stage = f.topStage as string;
    if (f.infiltration < BENIGN_T) stage = "Benign";
    else if (stage === "Benign") stage = lastAttack ?? stage;
    if (stage !== "Benign") lastAttack = stage;
    confFloor = Math.min(confFloor, f.confidence);
    return { ...f, topStage: stage as typeof f.topStage, confidence: confFloor };
  });

  return (
    <>
      <Topbar title="Attack Forecast Trajectory" sub="K-step forward simulation of learned transition dynamics P(Sₜ₊₁|Sₜ)" />

      <div className="main">
        {/* SIGNATURE FORECAST TIMELINE */}
        <div className="card" style={{ marginBottom: 20 }}>
          <ForecastTimeline
            forecast={steps}
            currentStage={r.currentStage}
            predictedStage={r.predictedStage}
            horizonSeconds={r.meta.horizonSeconds}
          />
        </div>

        {/* COMBINED INFILTRATION LINE CHART */}
        <Panel title="Observed vs Forecast Infiltration Trajectory" accent right={<span className="pill">Historical → Rollout</span>}>
          <LineChart
            height={240}
            series={[{ label: "Infiltration", color: COLORS.high, points: combined }]}
            markers={[{ x: nowX, label: "now", color: COLORS.brand }]}
          />
          <div className="legend" style={{ marginTop: 12 }}>
            <span><i style={{ background: COLORS.brand }} />Present Window (NOW)</span>
            <span><i style={{ background: COLORS.high }} />Infiltration Probability Trajectory</span>
            <span className="faint">Left of marker is observed sequence; right is {r.meta.K}-step forward simulation.</span>
          </div>
        </Panel>

        {/* STAGE FORECAST DETAIL & ASSESSMENT */}
        <div className="grid cols-2" style={{ marginTop: 20 }}>
          <Panel title="Step-by-Step Forecast Trajectory Matrix">
            <table>
              <thead>
                <tr>
                  <th>Horizon</th>
                  <th>Stage</th>
                  <th>Technique</th>
                  <th>Infiltration</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {steps.map((f) => (
                  <tr key={f.step}>
                    <td className="mono">{f.step === 0 ? "t (NOW)" : `t+${f.step}`}</td>
                    <td style={{ color: stageColor(f.topStage), fontWeight: 700 }}>{f.topStage}</td>
                    <td className="mono faint" style={{ fontSize: 11.5 }}>
                      {STAGE_TECHNIQUE[f.topStage] || "T1059"}
                    </td>
                    <td className="mono">{(f.infiltration * 100).toFixed(0)}%</td>
                    <td className="mono">{(f.confidence * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel title="World Model Assessment & Parameters">
            <Row k="Current Observed Stage" v={r.currentStage} c={stageColor(r.currentStage)} />
            <Row k="Predicted Next Stage" v={r.predictedStage} c={stageColor(r.predictedStage)} />
            <Row k="Mapped ATT&CK Technique" v={r.predictedTechnique} mono />
            <Row k="Current Infiltration Score" v={`${(r.currentInfiltration * 100).toFixed(0)}%`} />
            <Row k="Threat Level Assessment" v={r.threatLevel} c={stageColor(r.predictedStage)} />
            <Row k="Forecast Horizon" v={`${r.meta.K} steps · ${r.meta.horizonSeconds}s`} mono />
            <Row k="Lead Time vs IDS Baseline" v={`+${r.benchmark.leadSeconds}s (${r.benchmark.leadWindows} windows)`} c={COLORS.ok} />
            <p className="faint" style={{ fontSize: 11, marginTop: 14, lineHeight: 1.5 }}>
              Transitions are derived from behavioral evidence in the predicted latent state. Monotonic confidence decay accounts for compounding autoregressive uncertainty over the forecast horizon.
            </p>
          </Panel>
        </div>
      </div>
    </>
  );
}

function Row({ k, v, c, mono }: { k: string; v: string; c?: string; mono?: boolean }) {
  return (
    <div className="flex between center" style={{ padding: "9px 0", borderBottom: "1px solid var(--border-subtle)", fontSize: 12.5 }}>
      <span className="muted">{k}</span>
      <span className={mono ? "mono" : ""} style={{ color: c ?? "var(--text-primary)", fontWeight: 600 }}>
        {v}
      </span>
    </div>
  );
}
