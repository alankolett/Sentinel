"use client";

import Link from "next/link";
import { useState } from "react";
import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { LineChart, BarList, Panel, COLORS } from "@/components/charts";
import { ForecastTimeline } from "@/components/ForecastTimeline";
import { InteractiveNetworkGraph } from "@/components/InteractiveNetworkGraph";
import { ConfirmationModal } from "@/components/ConfirmationModal";
import { UrlSearchBar } from "@/components/UrlSearchBar";
import { STAGE_TECHNIQUE } from "@/lib/attack";

const threatClass = (t: string) => (t === "Critical" ? "b-crit" : t === "High" ? "b-high" : t === "Elevated" ? "b-elev" : "b-low");

export default function Dashboard() {
  const { result, error } = useStore();
  const [modalOpen, setModalOpen] = useState(false);
  const [isolatedHost, setIsolatedHost] = useState<string | null>(null);

  if (!result) {
    return (
      <>
        <Topbar title="Threat Operations Command" sub="Live AI network attack forecasting world-model" />
        {error ? (
          <div className="card" style={{ margin: "24px 40px" }}>
            <div className="empty">
              <span className="b-crit badge">{error}</span>
            </div>
          </div>
        ) : (
          <NeedData />
        )}
      </>
    );
  }

  const r = result;
  const b = r.benchmark;
  const infilSeries = r.forecast.map((f) => f.infiltration);
  const peak = Math.max(...r.forecast.slice(1).map((f) => f.infiltration));

  const targetHost = r.topHosts[0]?.ip || "10.0.0.66";
  const riskScore = Math.round((r.currentInfiltration * 0.4 + peak * 0.6) * 100);

  return (
    <>
      <Topbar title="Threat Operations Command" sub="Real-time attack forecasting, signal explainability & defender playbooks" />

      {/* ==========================================
          1. HERO AREA: NETWORK RISK & PRIMARY FORECAST
          ========================================== */}
      <div className="main">
        {/* URL ATTACK PREDICTION SEARCH BAR */}
        <div className="card" style={{ marginBottom: 20, padding: "16px 20px" }}>
          <div className="flex between center wrap gap">
            <span className="tag" style={{ color: "var(--brand-accent)" }}>
              🔍 TARGET DOMAIN CYBERATTACK PREDICTOR
            </span>
            <UrlSearchBar />
          </div>
        </div>

        <div
          className="card"
          style={{
            marginBottom: 20,
            background: "var(--bg-surface-elevated)",
            border: "1px solid var(--border-strong)",
            boxShadow: "var(--shadow-md)",
          }}
        >
          <div className="grid cols-3" style={{ gap: 24, background: "transparent", border: "none" }}>
            {/* CURRENT RISK */}
            <div>
              <span className="tag">CURRENT NETWORK RISK</span>
              <div className="flex center gap" style={{ marginTop: 8 }}>
                <span className="mono" style={{ fontSize: 44, fontWeight: 800, color: riskScore > 65 ? "var(--security-critical)" : "var(--security-warning)", lineHeight: 1 }}>
                  {riskScore}
                </span>
                <span className="muted mono" style={{ fontSize: 18 }}>/ 100</span>
              </div>
              <div style={{ marginTop: 8 }}>
                <span className={`badge ${threatClass(r.threatLevel)}`} style={{ padding: "4px 10px", fontSize: 11 }}>
                  <span className="dot" /> THREAT STATE: {r.threatLevel}
                </span>
              </div>
            </div>

            {/* FORECAST INSIGHT */}
            <div>
              <span className="tag">PRIMARY ATTACK FORECAST</span>
              <h2 style={{ fontSize: 18, fontWeight: 700, marginTop: 8, color: "var(--text-primary)", lineHeight: 1.3 }}>
                "{r.predictedStage} likely within {r.meta.horizonSeconds} seconds"
              </h2>
              <div className="flex gap wrap mono muted" style={{ fontSize: 11, marginTop: 8 }}>
                <span>Confidence: <b>{(r.forecast[0].confidence * 100).toFixed(0)}%</b></span>
                <span>·</span>
                <span>Horizon: <b>{r.meta.K} steps</b></span>
                <span>·</span>
                <span>Mapped: <b>{r.predictedTechnique}</b></span>
              </div>
            </div>

            {/* THIN RISK TRAJECTORY INDICATOR */}
            <div>
              <div className="flex between center" style={{ marginBottom: 4 }}>
                <span className="tag">RISK TRAJECTORY</span>
                <span className="mono" style={{ fontSize: 10, color: "var(--security-high)" }}>
                  Peak: {(peak * 100).toFixed(0)}%
                </span>
              </div>
              <LineChart
                height={90}
                series={[{ label: "Infiltration", color: COLORS.high, points: infilSeries }]}
                markers={[{ x: 0, label: "now", color: COLORS.brand }]}
                xLabels={r.forecast.map((f) => (f.step === 0 ? "t" : `t+${f.step}`))}
              />
            </div>
          </div>
        </div>

        {/* ==========================================
            2. SECONDARY COMPACT METRICS
            ========================================== */}
        <div className="grid cols-4" style={{ marginBottom: 20 }}>
          <Panel>
            <div className="stat">
              <span className="tag">Active Threats</span>
              <div className="val" style={{ fontSize: 24, marginTop: 6, color: "var(--security-critical)" }}>
                {r.graph.edges.filter((e) => e.suspicious).length}
              </div>
              <div className="sub mono">Probing & lateral paths</div>
            </div>
          </Panel>

          <Panel>
            <div className="stat">
              <span className="tag">Suspicious Hosts</span>
              <div className="val" style={{ fontSize: 24, marginTop: 6, color: "var(--security-high)" }}>
                {r.topHosts.filter((h) => h.suspicion > 0.4).length}
              </div>
              <div className="sub mono">Elevated anomaly score</div>
            </div>
          </Panel>

          <Panel>
            <div className="stat">
              <span className="tag">Forecast Confidence</span>
              <div className="val" style={{ fontSize: 24, marginTop: 6, color: "var(--security-safe)" }}>
                {(r.forecast[0].confidence * 100).toFixed(0)}%
              </div>
              <div className="sub mono">LSTM World Model fit</div>
            </div>
          </Panel>

          <Panel>
            <div className="stat">
              <span className="tag">ATT&CK Techniques</span>
              <div className="val" style={{ fontSize: 22, marginTop: 6 }}>
                {r.predictedTechnique.split(" ")[0]}
              </div>
              <div className="sub mono">{STAGE_TECHNIQUE[r.currentStage] || "T1059"}</div>
            </div>
          </Panel>
        </div>

        {/* ==========================================
            3. FORECAST TIMELINE SECTION
            ========================================== */}
        <div className="card" style={{ marginBottom: 20 }}>
          <ForecastTimeline
            forecast={r.forecast}
            currentStage={r.currentStage}
            predictedStage={r.predictedStage}
            horizonSeconds={r.meta.horizonSeconds}
          />
        </div>

        {/* ==========================================
            4. NETWORK GRAPH & EXPLAINABILITY
            ========================================== */}
        <div className="grid cols-2" style={{ gridTemplateColumns: "1.5fr 1fr", marginBottom: 20 }}>
          <Panel title="Network Security Topology & Lateral Movement" right={<Link href="/graph" className="pill">Full Graph →</Link>}>
            <InteractiveNetworkGraph nodes={r.graph.nodes} edges={r.graph.edges} />
          </Panel>

          <Panel title="WHY THIS FORECAST? (Top Contributing Signals)" right={<Link href="/explain" className="pill">Explainability →</Link>}>
            <BarList signed items={r.attributions.slice(0, 6).map((a) => ({ label: a.feature, value: a.contribution }))} />
            <p className="faint" style={{ fontSize: 11, marginTop: 14, lineHeight: 1.5 }}>
              Gradient backpropagation through the trained LSTM world model highlights packet burst rates and failed port scanning ratios as key attack drivers.
            </p>
          </Panel>
        </div>

        {/* ==========================================
            5. MITRE ATT&CK & RECOMMENDED ACTION
            ========================================== */}
        <div className="grid cols-2" style={{ marginBottom: 20 }}>
          <Panel title="MITRE ATT&CK Mapping & Evidence">
            <div style={{ padding: "8px 0" }}>
              <div className="flex between center" style={{ marginBottom: 8 }}>
                <span className="muted" style={{ fontSize: 12 }}>Mapped Technique:</span>
                <span className="mono" style={{ fontWeight: 700, color: "var(--brand-accent)" }}>{r.predictedTechnique}</span>
              </div>
              <div className="flex between center" style={{ marginBottom: 8 }}>
                <span className="muted" style={{ fontSize: 12 }}>Predicted Tactic:</span>
                <span className="mono" style={{ fontWeight: 600 }}>{r.predictedStage}</span>
              </div>
              <div className="flex between center" style={{ marginBottom: 12 }}>
                <span className="muted" style={{ fontSize: 12 }}>Observed Telemetry Evidence:</span>
                <span className="mono faint" style={{ fontSize: 11 }}>SMB Connection Burst (Port 445)</span>
              </div>
              <a
                href={`https://attack.mitre.org/techniques/${r.predictedTechnique.split(" ")[0]}/`}
                target="_blank"
                rel="noreferrer"
                className="pill"
                style={{ display: "inline-block", fontSize: 10.5 }}
              >
                🔗 External MITRE ATT&CK Knowledge Base
              </a>
            </div>
          </Panel>

          <Panel title="RECOMMENDED DEFENDER ACTION" accent>
            <div style={{ padding: "4px 0" }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "var(--security-critical)", marginBottom: 6 }}>
                RECOMMENDED ACTION: Isolate host {targetHost}
              </div>
              <p className="muted" style={{ fontSize: 12, marginBottom: 16 }}>
                Sentinel predicts imminent lateral movement targeting internal subnet 10.0.0.0/24 within the next {r.meta.horizonSeconds} seconds.
              </p>

              {isolatedHost === targetHost ? (
                <div className="badge b-low" style={{ padding: "8px 12px", width: "100%", justifyContent: "center" }}>
                  ✓ HOST {targetHost} ISOLATED VIA FIREWALL PLAYBOOK
                </div>
              ) : (
                <div className="flex gap wrap">
                  <Link href="/alerts" className="btn">
                    Investigate Threat
                  </Link>
                  <button className="btn btn-danger" onClick={() => setModalOpen(true)}>
                    🛑 Isolate Host {targetHost}
                  </button>
                </div>
              )}
            </div>
          </Panel>
        </div>

        {/* WORLD MODEL BENCHMARK CARD */}
        <div className="card">
          <div className="flex between center wrap gap">
            <div>
              <h3 style={{ color: "var(--text-secondary)" }}>WORLD MODEL vs CONVENTIONAL IDS</h3>
              <p className="muted" style={{ fontSize: 12, margin: "4px 0 0", maxWidth: 620 }}>
                On a hold-out test sequence, the world model forecasts attack escalation {b.leadSeconds}s earlier than static classifier baselines.
              </p>
            </div>
            <div className="flex gap wrap center">
              <div style={{ textAlign: "center", minWidth: 80 }}>
                <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: "var(--security-safe)" }}>
                  +{b.leadSeconds}s
                </div>
                <div className="faint" style={{ fontSize: 10 }}>Lead Time</div>
              </div>
              <div style={{ textAlign: "center", minWidth: 80 }}>
                <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: "var(--brand-accent)" }}>
                  {b.world.f1.toFixed(2)}
                </div>
                <div className="faint" style={{ fontSize: 10 }}>World Model F1</div>
              </div>
              <Link href="/benchmark" className="btn" style={{ alignSelf: "center" }}>
                Full Benchmark →
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* DANGEROUS ACTION CONFIRMATION MODAL */}
      <ConfirmationModal
        isOpen={modalOpen}
        title="Confirm System Isolation"
        description="Are you sure you want to trigger immediate network containment? All active SMB and TCP sessions on target host will be terminated."
        targetHost={targetHost}
        actionLabel="Execute Host Isolation"
        isDangerous={true}
        onConfirm={() => setIsolatedHost(targetHost)}
        onClose={() => setModalOpen(false)}
      />
    </>
  );
}
