"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Sentinel3DHero } from "@/components/Sentinel3DHero";

const PIPELINE_STEPS = [
  {
    step: "01",
    name: "Traffic Ingestion",
    detail: "PCAP / NetFlow",
    desc: "Ingests real-time network packets and NetFlow v9 streams via high-speed DPDK & Scapy packet capture listeners.",
    metrics: "12,450 pps · 10Gbps line rate",
    tech: "Scapy · Libpcap · DPDK",
  },
  {
    step: "02",
    name: "Feature Extract",
    detail: "21 Flow Features",
    desc: "Calculates 21 behavioral statistical flow features including packet inter-arrival times, payload entropy, and TCP window scaling.",
    metrics: "21 active flow vectors computed",
    tech: "NumPy · FlowParser Engine",
  },
  {
    step: "03",
    name: "Temporal State",
    detail: "Sequential Windows",
    desc: "Structures time-series flow records into sliding temporal windows to construct discrete network state representation S_t.",
    metrics: "Window size: 5.0s · Stride: 1.0s",
    tech: "Temporal Windowinging",
  },
  {
    step: "04",
    name: "LSTM Model",
    detail: "Learned Latent Space",
    desc: "Feed-forward through deep recurrent neural network to encode latent state transitions P(Sₜ₊₁|Sₜ).",
    metrics: "Latent dim: 128 · Loss: 0.042",
    tech: "PyTorch · LSTM Latent Space",
  },
  {
    step: "05",
    name: "K-Step Rollout",
    detail: "Forward Forecast",
    desc: "Simulates forward Monte-Carlo state trajectories up to 60 seconds into the future to predict attack progression.",
    metrics: "Horizon: T+60s · Confidence: 91%",
    tech: "World Model Rollout",
  },
  {
    step: "06",
    name: "Explainability",
    detail: "Feature Attribution",
    desc: "Applies Integrated Gradients and saliency mapping to isolate specific flow parameters driving the prediction.",
    metrics: "Top signal: SYN-ACK Ratio (38%)",
    tech: "Integrated Gradients",
  },
  {
    step: "07",
    name: "MITRE ATT&CK",
    detail: "Technique Mapping",
    desc: "Correlates state trajectory probabilities directly to MITRE ATT&CK Enterprise tactics and TTP identifiers.",
    metrics: "Predicted TTP: T1021 (Lateral Move)",
    tech: "MITRE ATT&CK Matrix v14",
  },
  {
    step: "08",
    name: "Defender Action",
    detail: "SOC Playbooks",
    desc: "Generates analyst-verified automated defense playbooks for host isolation, firewall policy updates, and session kill.",
    metrics: "Automated Playbook: ISOLATE-HOST-66",
    tech: "SOAR API · IPtables / AWS Security Group",
  },
];

export default function LandingPage() {
  const [activeStep, setActiveStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);

  // Auto-cycle through process flow steps unless paused
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % PIPELINE_STEPS.length);
    }, 2200);
    return () => clearInterval(interval);
  }, [isPlaying]);

  const currentStepInfo = PIPELINE_STEPS[activeStep];

  return (
    <div
      className="landing-editorial"
      style={{
        background: "var(--bg-canvas)",
        color: "var(--text-primary)",
        minHeight: "100vh",
        padding: "0 0 80px",
        position: "relative",
      }}
    >
      {/* Ambient Lighting & Grid Glow Background Overlay */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 640,
          background: "radial-gradient(ellipse at 65% 25%, rgba(59, 130, 246, 0.14), transparent 60%), radial-gradient(ellipse at 20% 40%, rgba(37, 99, 235, 0.08), transparent 50%)",
          pointerEvents: "none",
          zIndex: 0,
        }}
      />

      {/* SECTION 1 — HERO */}
      <section
        style={{
          position: "relative",
          zIndex: 1,
          maxWidth: 1240,
          margin: "0 auto",
          padding: "60px 40px 40px",
          display: "grid",
          gridTemplateColumns: "1.1fr 1fr",
          gap: 40,
          alignItems: "center",
        }}
      >
        <div>
          <div className="eyebrow" style={{ marginBottom: 16 }}>
            AI-POWERED CYBER DEFENSE<i />
          </div>
          <h1
            style={{
              fontSize: "clamp(44px, 5.8vw, 68px)",
              fontWeight: 800,
              letterSpacing: "-0.04em",
              lineHeight: 1.02,
              marginBottom: 22,
              color: "var(--text-primary)",
            }}
          >
            DETECT WHAT’S <br />
            COMING NEXT.
          </h1>
          <p
            style={{
              fontSize: 16,
              color: "var(--text-secondary)",
              lineHeight: 1.6,
              marginBottom: 36,
              maxWidth: 530,
            }}
          >
            Sentinel transforms live network traffic into temporal attack forecasts, explaining what is likely to happen next before the attack progresses.
          </p>

          <div className="flex gap wrap" style={{ gap: 14 }}>
            <Link href="/dashboard" className="btn btn-primary" style={{ padding: "14px 28px", fontSize: 13, fontWeight: 700 }}>
              Explore Sentinel →
            </Link>
            <a href="#architecture" className="btn" style={{ padding: "14px 22px", fontSize: 13 }}>
              View Architecture
            </a>
          </div>
        </div>

        {/* Hero Interactive 3D World Model Mesh Visual */}
        <div
          className="card"
          style={{
            background: "rgba(15, 21, 36, 0.65)",
            backdropFilter: "blur(12px)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius)",
            padding: 0,
            boxShadow: "var(--shadow-lg)",
            overflow: "hidden",
          }}
        >
          <Sentinel3DHero />
        </div>
      </section>

      {/* NTRO PROBLEM STATEMENT SIH26153 EXECUTIVE BRIEF CARD */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: 1240, margin: "0 auto 40px", padding: "0 40px" }}>
        <div
          className="card"
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-strong)",
            borderRadius: "var(--radius)",
            padding: "24px 28px",
            boxShadow: "var(--shadow-md), 0 0 24px -6px rgba(59, 130, 246, 0.12)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16, marginBottom: 18, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span className="badge b-info" style={{ fontSize: 11, padding: "4px 10px", fontWeight: 700 }}>
                SIH26153 COMPLIANT
              </span>
              <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-tertiary)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                National Technical Research Organisation (NTRO) · Space Technology
              </span>
            </div>
            <div style={{ fontSize: 11.5, color: "var(--text-tertiary)", fontWeight: 600 }}>
              Dataset: CSE-CIC-IDS2018 Infiltration Benchmark
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20 }}>
            <div>
              <div style={{ fontSize: 10.5, color: "var(--text-tertiary)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
                PROBLEM STATEMENT
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>
                AI Network Attack Forecasting
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
                Time-series traffic state prediction
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, color: "var(--text-tertiary)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
                CORE ARCHITECTURE
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>
                Dual-Head LSTM World Model
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
                P(Sₜ₊₁|Sₜ) + K-step rollout
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, color: "var(--text-tertiary)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
                FORECAST LEAD TIME
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--security-safe)" }}>
                +20 Seconds Advantage
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
                2 windows prior to single-flow NIDS
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10.5, color: "var(--text-tertiary)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
                RECALL @ 5% FPR BUDGET
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--brand-accent)" }}>
                60.6% vs 13.5% Baseline
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
                4.5× recall gain over standard LR
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 2 — EDITORIAL STATEMENT */}
      <section
        style={{
          position: "relative",
          zIndex: 1,
          background: "var(--bg-surface-muted)",
          borderTop: "1px solid var(--border-subtle)",
          borderBottom: "1px solid var(--border-subtle)",
          padding: "72px 40px",
          textAlign: "center",
        }}
      >
        <div style={{ maxWidth: 860, margin: "0 auto" }}>
          <h2
            style={{
              fontSize: "clamp(28px, 4vw, 44px)",
              fontWeight: 700,
              letterSpacing: "-0.03em",
              lineHeight: 1.2,
              marginBottom: 16,
              color: "var(--text-primary)",
            }}
          >
            “Detection tells you what happened. <br />
            Forecasting tells you what happens next.”
          </h2>
          <p style={{ fontSize: 15, color: "var(--text-secondary)", maxWidth: 640, margin: "0 auto" }}>
            Conventional Intrusion Detection Systems fire alerts after assets are breached. Sentinel models temporal transition dynamics to anticipate attack trajectory before compromise occurs.
          </p>
        </div>
      </section>

      {/* SECTION 3 — THREE CORE FEATURE BLOCKS */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: 1240, margin: "80px auto", padding: "0 40px" }}>
        <div className="grid cols-3 gap">
          <div className="card" style={{ padding: 32 }}>
            <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--brand-accent)", marginBottom: 12 }}>
              01
            </div>
            <h3 style={{ fontSize: 18, textTransform: "none", letterSpacing: "-0.01em", color: "var(--text-primary)", marginBottom: 8 }}>
              FORECAST
            </h3>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
              Predict the next likely attack stage forward in time using learned world-model transition dynamics P(Sₜ₊₁|Sₜ).
            </p>
          </div>

          <div className="card" style={{ padding: 32 }}>
            <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--brand-accent)", marginBottom: 12 }}>
              02
            </div>
            <h3 style={{ fontSize: 18, textTransform: "none", letterSpacing: "-0.01em", color: "var(--text-primary)", marginBottom: 8 }}>
              EXPLAIN
            </h3>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
              Understand precisely which network signals and temporal windows contributed to the forecast with gradient-based saliency.
            </p>
          </div>

          <div className="card" style={{ padding: 32 }}>
            <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: "var(--brand-accent)", marginBottom: 12 }}>
              03
            </div>
            <h3 style={{ fontSize: 18, textTransform: "none", letterSpacing: "-0.01em", color: "var(--text-primary)", marginBottom: 8 }}>
              RESPOND
            </h3>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
              Map predictions directly to MITRE ATT&CK techniques and trigger automated, analyst-confirmed host isolation playbooks.
            </p>
          </div>
        </div>
      </section>

      {/* SECTION 4 — INTERACTIVE PROCESS FLOW ARCHITECTURE PIPELINE */}
      <section
        id="architecture"
        style={{
          position: "relative",
          zIndex: 1,
          background: "var(--bg-surface)",
          borderTop: "1px solid var(--border-subtle)",
          borderBottom: "1px solid var(--border-subtle)",
          padding: "80px 40px",
        }}
      >
        <div style={{ maxWidth: 1240, margin: "0 auto" }}>
          <div className="flex between center wrap gap" style={{ marginBottom: 24 }}>
            <div>
              <div className="eyebrow" style={{ marginBottom: 8 }}>
                SYSTEM PIPELINE<i />
              </div>
              <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.02em" }}>
                Sentinel World Model Architecture
              </h2>
            </div>

            {/* Simulation Controls */}
            <div className="flex center gap">
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className="btn"
                style={{ fontSize: 12, padding: "6px 14px", display: "flex", alignItems: "center", gap: 6 }}
              >
                {isPlaying ? "⏸ Pause Flow" : "▶ Play Flow"}
              </button>
            </div>
          </div>

          {/* 8-Step Interactive Pipeline Strip */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
              gap: 12,
              marginBottom: 24,
            }}
          >
            {PIPELINE_STEPS.map((p, idx) => {
              const isActive = idx === activeStep;
              return (
                <div
                  key={p.step}
                  onClick={() => {
                    setActiveStep(idx);
                    setIsPlaying(false);
                  }}
                  className="card"
                  style={{
                    padding: "16px 12px",
                    textAlign: "center",
                    cursor: "pointer",
                    border: isActive ? "1px solid var(--brand-accent)" : "1px solid var(--border-subtle)",
                    background: isActive ? "var(--brand-primary-muted)" : "var(--bg-surface)",
                    boxShadow: isActive ? "0 4px 16px rgba(59, 130, 246, 0.2)" : "none",
                    transform: isActive ? "translateY(-3px)" : "none",
                    transition: "all 0.25s cubic-bezier(0.16, 1, 0.3, 1)",
                  }}
                >
                  <div
                    className="mono"
                    style={{
                      fontSize: 11,
                      color: isActive ? "var(--brand-accent)" : "var(--text-tertiary)",
                      fontWeight: 700,
                    }}
                  >
                    {p.step} {isActive ? "▶" : ""}
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)", margin: "4px 0 2px" }}>
                    {p.name}
                  </div>
                  <div className="mono faint" style={{ fontSize: 9.5 }}>
                    {p.detail}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Active Step Detailed Information Panel */}
          <div
            className="card"
            style={{
              padding: 24,
              background: "var(--bg-surface-elevated)",
              border: "1px solid var(--border-default)",
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 24,
              alignItems: "center",
            }}
          >
            <div>
              <div className="flex center gap" style={{ marginBottom: 8 }}>
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--brand-accent)" }}>
                  STAGE {currentStepInfo.step} OF 08
                </span>
                <span className="badge b-info" style={{ borderRadius: 4 }}>
                  {currentStepInfo.name}
                </span>
              </div>
              <h3 style={{ fontSize: 20, fontWeight: 700, textTransform: "none", color: "var(--text-primary)", marginBottom: 8 }}>
                {currentStepInfo.name} ({currentStepInfo.detail})
              </h3>
              <p style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                {currentStepInfo.desc}
              </p>
            </div>

            <div style={{ background: "var(--bg-canvas)", padding: 16, borderRadius: "var(--radius)", border: "1px solid var(--border-subtle)" }}>
              <div className="tag" style={{ marginBottom: 8 }}>STAGE TELEMETRY & STACK</div>
              <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--security-safe)", marginBottom: 6 }}>
                ● {currentStepInfo.metrics}
              </div>
              <div className="mono faint" style={{ fontSize: 11 }}>
                Engine Stack: {currentStepInfo.tech}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 5 — DASHBOARD PREVIEW TEASER */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: 1240, margin: "80px auto 40px", padding: "0 40px" }}>
        <div className="card" style={{ padding: 40, background: "var(--bg-surface-elevated)", border: "1px solid var(--border-default)" }}>
          <div className="flex between center wrap gap" style={{ marginBottom: 24 }}>
            <div>
              <span className="tag">DASHBOARD PREVIEW</span>
              <h2 style={{ fontSize: 26, fontWeight: 700, marginTop: 4 }}>Live Threat Operations Command</h2>
            </div>
            <Link href="/dashboard" className="btn btn-primary">
              Launch Live Dashboard →
            </Link>
          </div>

          <div
            style={{
              padding: 24,
              background: "var(--bg-canvas)",
              borderRadius: "var(--radius)",
              border: "1px solid var(--border-subtle)",
            }}
          >
            <div className="grid cols-3 gap">
              <div>
                <span className="tag">CURRENT RISK SCORE</span>
                <div className="mono" style={{ fontSize: 36, fontWeight: 800, color: "var(--security-critical)", marginTop: 6 }}>
                  82 / 100
                </div>
                <span className="badge b-crit" style={{ marginTop: 4 }}>HIGH RISK</span>
              </div>
              <div>
                <span className="tag">PRIMARY FORECAST</span>
                <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)", marginTop: 6 }}>
                  Lateral Movement predicted in T+20s
                </div>
                <div className="mono faint" style={{ fontSize: 11, marginTop: 2 }}>Confidence: 91% · Horizon: 50s</div>
              </div>
              <div>
                <span className="tag">RECOMMENDED DEFENDER ACTION</span>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--security-safe)", marginTop: 6 }}>
                  Isolate Compromised Host 10.0.0.66
                </div>
                <button className="btn btn-primary" style={{ marginTop: 8, fontSize: 11, padding: "5px 10px" }}>
                  Execute Isolation Playbook
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 6 — TECHNICAL CREDIBILITY */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: 1240, margin: "0 auto 40px", padding: "0 40px", textAlign: "center" }}>
        <div className="tag" style={{ marginBottom: 12 }}>ENGINEERING STACK & STANDARDS</div>
        <div
          className="mono"
          style={{
            display: "flex",
            gap: 24,
            justifyContent: "center",
            flexWrap: "wrap",
            fontSize: 13,
            fontWeight: 600,
            color: "var(--text-secondary)",
          }}
        >
          <span>Python</span>
          <span>·</span>
          <span>PyTorch</span>
          <span>·</span>
          <span>LSTM World Model</span>
          <span>·</span>
          <span>Scapy</span>
          <span>·</span>
          <span>FastAPI</span>
          <span>·</span>
          <span>React 19 / Next.js</span>
          <span>·</span>
          <span>MITRE ATT&CK</span>
          <span>·</span>
          <span>CIC-IDS2018</span>
        </div>
      </section>

      {/* FOOTER */}
      <footer style={{ position: "relative", zIndex: 1, borderTop: "1px solid var(--border-subtle)", paddingTop: 32, textAlign: "center" }}>
        <div className="mono faint" style={{ fontSize: 11 }}>
          SENTINEL — SIH 2026 Problem Statement 26153 · NTRO Cybersecurity Division
        </div>
      </footer>
    </div>
  );
}
