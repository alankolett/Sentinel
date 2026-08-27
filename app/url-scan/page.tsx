"use client";

import { Topbar } from "@/components/shell";
import { UrlSearchBar } from "@/components/UrlSearchBar";

export default function UrlScanPage() {
  return (
    <>
      <Topbar title="URL Cyberattack Predictor" sub="Enter any domain or URL to forecast ongoing attacks with Groq & Gemini AI" />

      <div className="main">
        <div className="card" style={{ marginBottom: 24, background: "var(--bg-surface-elevated)", border: "1px solid var(--border-strong)", padding: 32 }}>
          <div style={{ maxWidth: 720, margin: "0 auto", textAlign: "center" }}>
            <span className="tag" style={{ color: "var(--brand-accent)" }}>
              AI DOMAIN THREAT INTELLIGENCE
            </span>
            <h2 style={{ fontSize: 28, fontWeight: 800, marginTop: 8, marginBottom: 12, color: "var(--text-primary)" }}>
              Is your target domain under cyberattack?
            </h2>
            <p className="muted" style={{ fontSize: 14, marginBottom: 28, lineHeight: 1.6 }}>
              Enter any target website domain, IP address, or URL below. Sentinel leverages real-time telemetry metrics and Groq / Gemini LLMs to forecast active probing, DDoS bursts, and lateral movement escalation.
            </p>

            <div style={{ display: "flex", justifyContent: "center" }}>
              <UrlSearchBar />
            </div>
          </div>
        </div>

        <div className="grid cols-3 gap">
          <div className="card">
            <div className="mono" style={{ fontSize: 20, fontWeight: 800, color: "var(--brand-accent)", marginBottom: 8 }}>
              ⚡ Groq Llama-3.3
            </div>
            <h3 style={{ fontSize: 14, textTransform: "none", color: "var(--text-primary)" }}>Ultra-Fast Inference</h3>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
              Sub-second threat classification using Groq's high-speed Llama 70B architecture.
            </p>
          </div>

          <div className="card">
            <div className="mono" style={{ fontSize: 20, fontWeight: 800, color: "var(--security-safe)", marginBottom: 8 }}>
              ✨ Gemini 2.5 Flash
            </div>
            <h3 style={{ fontSize: 14, textTransform: "none", color: "var(--text-primary)" }}>Multi-Signal Reasoning</h3>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
              Deep domain intelligence evaluating DNS query ratios, SSL integrity, and HTTP burst patterns.
            </p>
          </div>

          <div className="card">
            <div className="mono" style={{ fontSize: 20, fontWeight: 800, color: "var(--security-high)", marginBottom: 8 }}>
              🛡️ World Model Fallback
            </div>
            <h3 style={{ fontSize: 14, textTransform: "none", color: "var(--text-primary)" }}>Offline Zero-Trust</h3>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
              Automatic fallback to local LSTM state transition dynamics if no API key is specified.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
