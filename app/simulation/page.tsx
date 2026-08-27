"use client";

import { useEffect, useState } from "react";
import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { Gauge, LineChart, BarList, Panel, COLORS } from "@/components/charts";
import { MitreMatrix } from "@/components/MitreMatrix";
import { STAGE_TECHNIQUE } from "@/lib/attack";
import type { AnalysisResult } from "@/lib/analyze";

export default function SimulationPage() {
  const { result, error, loadDemo, loading } = useStore();
  const [tick, setTick] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);

  // Auto-load demo if no result is present
  useEffect(() => {
    if (!result && !error && !loading) {
      loadDemo();
    }
  }, [result, error, loading, loadDemo]);

  // Simulation loop
  useEffect(() => {
    if (!result || !isPlaying) return;
    
    // Create a fake live stream by advancing a tick every 1000ms.
    // In a real system, this would be a WebSocket pulling `r.forecast[0]` sequentially.
    const interval = setInterval(() => {
      setTick(t => Math.min(t + 1, 100)); // cap at 100 ticks for demo
    }, 1000);
    return () => clearInterval(interval);
  }, [result, isPlaying]);

  if (!result) {
    return (
      <>
        <Topbar title="Live Simulation" sub="War Room SOC Dashboard" />
        {error ? <div className="card"><div className="empty"><span className="high">{error}</span></div></div> : <NeedData />}
      </>
    );
  }

  const r = result;
  
  // Simulate live data progression based on 'tick'
  // We'll interpolate some values to make them look like they are rising over time
  const progress = Math.min(1, (tick + 10) / 60); // 60 seconds to full severity
  
  // Interpolated values for simulation
  const simInfil = r.forecast[0].infiltration * progress;
  const simConfidence = r.forecast[0].confidence * progress;
  const infilSeries = r.forecast.map((f) => f.infiltration * progress);
  
  // Stages that evolve over time
  const stages: string[] = ["Reconnaissance", "Initial Access", "Execution", "Lateral Movement", "Exfiltration"];
  const currentStageIdx = Math.min(Math.floor(progress * stages.length), stages.length - 1);
  const currentStage = stages[currentStageIdx] as any;
  const predictedStage = (currentStageIdx + 1 < stages.length) ? stages[currentStageIdx + 1] as any : currentStage;

  const [autoMitigate, setAutoMitigate] = useState(true);
  const [mitigationLog, setMitigationLog] = useState<string | null>(null);

  useEffect(() => {
    if (autoMitigate && simInfil > 0.4) {
      setMitigationLog("🛡️ AUTOMATED SOAR PLAYBOOK EXECUTED: Host 192.168.1.105 Isolated · IP Filter Enforced · Session Revoked");
    } else {
      setMitigationLog(null);
    }
  }, [autoMitigate, simInfil]);

  return (
    <>
      <div className="topbar" style={{ paddingBottom: 10, marginBottom: 15 }}>
        <div className="topbar-lead">
          <span className="eyebrow"><span className="dot" style={{ display: 'inline-block', width: 8, height: 8, background: isPlaying ? 'var(--warn)' : 'var(--muted)', borderRadius: '50%', marginRight: 8, animation: isPlaying ? 'blink 1.5s infinite' : 'none' }}></span>Live Simulation<i /></span>
          <h1 className="display" style={{ marginTop: 0, fontSize: 24 }}>SOC War Room</h1>
        </div>
        <div className="flex gap" style={{ alignItems: "center" }}>
          <button
            className="btn"
            onClick={() => setAutoMitigate(!autoMitigate)}
            style={{
              fontSize: 11,
              fontWeight: 700,
              background: autoMitigate ? "var(--security-safe-bg)" : "var(--bg-surface-muted)",
              color: autoMitigate ? "var(--security-safe)" : "var(--text-secondary)",
              border: autoMitigate ? "1px solid rgba(16, 185, 129, 0.3)" : "1px solid var(--border-default)",
            }}
          >
            ⚡ SOAR Auto-Mitigation: {autoMitigate ? "ACTIVE" : "OFF"}
          </button>
          <button className="btn btn-outline" onClick={() => setTick(0)}>↺ Restart</button>
          <button className="btn btn-primary" onClick={() => setIsPlaying(!isPlaying)}>
            {isPlaying ? "⏸ Pause" : "▶ Resume"}
          </button>
        </div>
      </div>

      {mitigationLog && (
        <div
          style={{
            margin: "0 40px 16px",
            padding: "10px 16px",
            background: "var(--security-safe-bg)",
            border: "1px solid rgba(16, 185, 129, 0.4)",
            borderRadius: "var(--radius, 6px)",
            color: "var(--security-safe)",
            fontSize: 12,
            fontWeight: 700,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>{mitigationLog}</span>
          <span style={{ fontSize: 10, fontFamily: "var(--mono)", opacity: 0.8 }}>RESPONSE TIME: 14ms</span>
        </div>
      )}

      <div className="grid cols-4" style={{ gridTemplateAreas: `
        "gauge gauge forecast forecast"
        "matrix matrix matrix matrix"
        "attrib attrib hosts hosts"
      `, gap: '14px', background: 'transparent', border: 'none', boxShadow: 'none' }}>
        
        {/* Threat Gauge */}
        <div style={{ gridColumn: 'span 1' }}>
          <Panel accent title="Live Threat Level">
             <div style={{ display: "grid", placeItems: "center", padding: "10px 0 20px" }}>
              <Gauge value={simInfil} label="infil probability" sublabel={`confidence ${(simConfidence * 100).toFixed(0)}%`} />
            </div>
            <div className="flex between center">
              <span className="tag">Simulated Time</span>
              <span className="mono" style={{ color: 'var(--ink)' }}>t + {tick}s</span>
            </div>
          </Panel>
        </div>

        {/* Forecast Trajectory */}
        <div style={{ gridColumn: 'span 3' }}>
          <Panel title="Real-Time Trajectory Forecast">
            <LineChart height={220}
              series={[{ label: "Infiltration", color: COLORS.high, points: infilSeries }]}
              markers={[{ x: 0, label: "now", color: COLORS.brand }]}
              xLabels={r.forecast.map((f) => (f.step === 0 ? "t" : `t+${f.step}`))} />
          </Panel>
        </div>

        {/* MITRE Matrix */}
        <div style={{ gridColumn: 'span 4' }}>
          <Panel title="Predicted Kill-Chain Progression">
            <MitreMatrix currentStage={currentStage} predictedStage={predictedStage} />
          </Panel>
        </div>

        {/* Attribution Heatmap (Simplified via BarList) */}
        <div style={{ gridColumn: 'span 2' }}>
          <Panel title="Live Feature Attribution">
             {/* Scale the values to simulate evolution */}
            <BarList signed items={r.attributions.slice(0, 5).map((a) => ({ label: a.feature, value: a.contribution * progress }))} />
          </Panel>
        </div>

        {/* Live Event Ticker */}
        <div style={{ gridColumn: 'span 2' }}>
          <Panel title="Event Ticker">
            <div style={{ height: 200, overflowY: 'auto', background: 'var(--bg-2)', padding: 10, borderRadius: 4, fontFamily: 'var(--mono)', fontSize: 11, border: '1px solid var(--line)' }}>
              {Array.from({ length: Math.min(tick, 20) }).reverse().map((_, i) => (
                <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--line-2)', color: i === 0 ? 'var(--text)' : 'var(--muted)' }}>
                  <span style={{ color: 'var(--brand)' }}>[T+{tick - i}s]</span> Event parsed from stream window...
                </div>
              ))}
              {tick === 0 && <div className="muted">Waiting for data...</div>}
            </div>
          </Panel>
        </div>

      </div>
    </>
  );
}
