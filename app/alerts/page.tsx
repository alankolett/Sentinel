"use client";

import { useState } from "react";
import { Topbar } from "@/components/shell";
import { BarList, Panel } from "@/components/charts";
import { ConfirmationModal } from "@/components/ConfirmationModal";

export default function ThreatInvestigationPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const [isIsolated, setIsIsolated] = useState(false);

  const timelineEvents = [
    { time: "14:02:11", title: "Suspicious inbound traffic anomaly", detail: "Burst from 10.0.0.42 targeting internal subnet", level: "Elevated" },
    { time: "14:02:18", title: "Port scanning activity detected", detail: "Probing ports 135, 139, 445 across 24 hosts", level: "High" },
    { time: "14:02:27", title: "Credential-related anomaly", detail: "Repeated NTLM authentication failures", level: "High" },
    { time: "14:02:41", title: "Lateral movement predicted", detail: "World Model forecasts escalation within 50s", level: "Critical" },
    { time: "14:02:53", title: "ATT&CK T1021 technique mapped", detail: "Remote Services / SMB connection burst", level: "Critical" },
  ];

  const topAttributions = [
    { label: "SYN packet rate", value: 0.34 },
    { label: "Failed connection count", value: 0.22 },
    { label: "Port scanning activity", value: 0.18 },
    { label: "Destination diversity", value: 0.14 },
    { label: "Temporal connection burst", value: 0.12 },
  ];

  return (
    <>
      <Topbar title="Threat Investigation" sub="Deep-dive incident forensics, evidence breakdown & attack trajectory" />

      <div className="main">
        {/* SOC INCIDENT INVESTIGATION HEADER */}
        <div className="card" style={{ marginBottom: 20, background: "var(--bg-surface-elevated)", border: "1px solid var(--border-strong)" }}>
          <div className="flex between center wrap gap">
            <div>
              <div className="flex center gap" style={{ marginBottom: 6 }}>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--text-tertiary)" }}>
                  INCIDENT ID:
                </span>
                <span className="mono" style={{ fontSize: 18, fontWeight: 800, color: "var(--brand-accent)" }}>
                  THR-2026-00142
                </span>
                <span className="badge b-crit">STATUS: ACTIVE</span>
              </div>
              <p className="muted" style={{ fontSize: 13 }}>
                Target System: <strong className="mono">10.0.0.66</strong> (Internal Server) · Source: <strong className="mono">10.0.0.42</strong>
              </p>
            </div>

            <div className="flex gap wrap center" style={{ gap: 20 }}>
              <div style={{ textAlign: "right" }}>
                <span className="tag">SEVERITY</span>
                <div style={{ fontSize: 18, fontWeight: 700, color: "var(--security-critical)" }}>HIGH</div>
              </div>
              <div style={{ textAlign: "right" }}>
                <span className="tag">MODEL CONFIDENCE</span>
                <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: "var(--security-safe)" }}>87%</div>
              </div>
            </div>
          </div>
        </div>

        {/* CHRONOLOGICAL TIMELINE & EVIDENCE GRID */}
        <div className="grid cols-2" style={{ gridTemplateColumns: "1fr 1.2fr", marginBottom: 20 }}>
          {/* CHRONOLOGICAL ATTACK TIMELINE */}
          <Panel title="Attack Sequence Timeline">
            <div style={{ position: "relative", paddingLeft: 20, borderLeft: "2px solid var(--border-default)", display: "flex", flexDirection: "column", gap: 16 }}>
              {timelineEvents.map((ev, i) => (
                <div key={i} style={{ position: "relative" }}>
                  <div
                    style={{
                      position: "absolute",
                      left: -26,
                      top: 2,
                      width: 10,
                      height: 10,
                      borderRadius: "50%",
                      background: ev.level === "Critical" ? "var(--security-critical)" : "var(--security-warning)",
                      boxShadow: "0 0 0 3px var(--bg-surface)",
                    }}
                  />
                  <div className="flex between center">
                    <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: "var(--text-tertiary)" }}>
                      {ev.time}
                    </span>
                    <span className={`badge ${ev.level === "Critical" ? "b-crit" : "b-elev"}`} style={{ fontSize: 8.5 }}>
                      {ev.level}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 650, color: "var(--text-primary)", marginTop: 2 }}>
                    {ev.title}
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                    {ev.detail}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* GROUPED EVIDENCE */}
          <Panel title="Grouped Incident Evidence">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div style={{ padding: 12, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
                <span className="tag">NETWORK EVIDENCE</span>
                <div style={{ marginTop: 6, fontSize: 12 }} className="mono">
                  <div>Source: <b>10.0.0.42</b></div>
                  <div>Dest: <b>10.0.0.66</b></div>
                  <div>Protocol: <b>TCP / SMB</b></div>
                  <div>Port: <b>445</b></div>
                  <div>Packets: <b>14,293</b></div>
                </div>
              </div>

              <div style={{ padding: 12, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
                <span className="tag">HOST TELEMETRY</span>
                <div style={{ marginTop: 6, fontSize: 12 }} className="mono">
                  <div>OS: <b>Ubuntu 22.04</b></div>
                  <div>Role: <b>Domain Controller</b></div>
                  <div>Auth Failures: <b>142</b></div>
                  <div>Active Cons: <b>18</b></div>
                </div>
              </div>

              <div style={{ padding: 12, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
                <span className="tag">TEMPORAL SALIENCY</span>
                <div style={{ marginTop: 6, fontSize: 12 }}>
                  <div>Window: <b>T-50s to T-10s</b></div>
                  <div>Burst Ratio: <b>+340%</b></div>
                  <div>Inter-arrival: <b>0.4ms</b></div>
                </div>
              </div>

              <div style={{ padding: 12, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)" }}>
                <span className="tag">BEHAVIORAL SIGNAL</span>
                <div style={{ marginTop: 6, fontSize: 12 }}>
                  <div>Pattern: <b>SMB Burst</b></div>
                  <div>Peer Fanout: <b>High</b></div>
                  <div>Dst Diversity: <b>24 IPs</b></div>
                </div>
              </div>
            </div>
          </Panel>
        </div>

        {/* FORECAST & EXPLAINABILITY */}
        <div className="grid cols-2" style={{ marginBottom: 20 }}>
          <Panel title="Attack Stage Forecast & MITRE ATT&CK">
            <div style={{ padding: "4px 0" }}>
              <div className="flex between center" style={{ marginBottom: 10 }}>
                <span className="muted">Current Observed Stage:</span>
                <span className="badge b-elev">Discovery</span>
              </div>
              <div className="flex between center" style={{ marginBottom: 10 }}>
                <span className="muted">Predicted Next Stage:</span>
                <span className="badge b-crit">Lateral Movement (T1021)</span>
              </div>
              <div className="flex between center" style={{ marginBottom: 10 }}>
                <span className="muted">Probability Intensity:</span>
                <span className="mono" style={{ fontWeight: 700, color: "var(--security-critical)" }}>82%</span>
              </div>
              <div className="flex between center" style={{ marginBottom: 10 }}>
                <span className="muted">Forecast Horizon:</span>
                <span className="mono">50 Seconds</span>
              </div>
              <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-subtle)" }}>
                <span className="tag">MAPPED TECHNIQUE</span>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)", marginTop: 4 }}>
                  T1021 — Remote Services (SMB)
                </div>
                <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                  Evidence: Repeated SMB session establishment bursts without valid SMB2 session teardowns.
                </div>
              </div>
            </div>
          </Panel>

          <Panel title="Top Feature Attributions (Why Sentinel Forecasted This)">
            <BarList signed items={topAttributions} />
          </Panel>
        </div>

        {/* RECOMMENDED SOC RESPONSE ACTIONS */}
        <div className="card">
          <h3 style={{ color: "var(--text-secondary)", marginBottom: 12 }}>RECOMMENDED SOC DEFENDER PLAYBOOKS</h3>
          <div className="flex between center wrap gap">
            <div className="flex gap wrap">
              <button className="btn" onClick={() => alert("Detailed packet inspection log generated.")}>
                🔍 Inspect Raw Traffic
              </button>
              <button className="btn" onClick={() => alert("Incident ticket THR-2026-00142 created in SOAR.")}>
                📋 Create Incident Ticket
              </button>
              <button className="btn" onClick={() => alert("Host memory dump scheduled.")}>
                💾 Schedule Memory Dump
              </button>
            </div>

            {isIsolated ? (
              <div className="badge b-low" style={{ padding: "8px 14px" }}>
                ✓ HOST 10.0.0.66 ISOLATED FROM SUBNET
              </div>
            ) : (
              <button className="btn btn-danger" onClick={() => setModalOpen(true)}>
                🛑 Isolate Host 10.0.0.66
              </button>
            )}
          </div>
        </div>
      </div>

      <ConfirmationModal
        isOpen={modalOpen}
        title="Confirm Host Containment"
        description="Executing host isolation will sever all active SMB, TCP, and SSH sessions for host 10.0.0.66 to prevent lateral movement."
        targetHost="10.0.0.66"
        actionLabel="Execute Host Isolation"
        isDangerous={true}
        onConfirm={() => setIsIsolated(true)}
        onClose={() => setModalOpen(false)}
      />
    </>
  );
}
