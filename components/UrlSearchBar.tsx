"use client";

import { useState } from "react";
import { scanTargetUrl, type UrlScanResult } from "@/lib/urlScan";

export function UrlSearchBar() {
  const [urlInput, setUrlInput] = useState("");
  const [provider, setProvider] = useState<"auto" | "groq" | "gemini">("auto");
  const [apiKey, setApiKey] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<UrlScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!urlInput.trim()) return;

    setLoading(true);
    try {
      const res = await scanTargetUrl(urlInput, provider, apiKey);
      setResult(res);
    } catch {
      /* noop */
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ width: "100%", maxWidth: 680, position: "relative" }}>
      {/* URL SEARCH INPUT BAR */}
      <form onSubmit={handleScan} className="flex center gap" style={{ width: "100%" }}>
        <div style={{ position: "relative", flex: 1 }}>
          <input
            type="text"
            placeholder="Enter website URL or domain (e.g. target.com, https://company.org)..."
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            style={{
              width: "100%",
              padding: "10px 14px 10px 36px",
              fontSize: 13,
              background: "var(--bg-surface-muted)",
              border: "1px solid var(--border-default)",
              borderRadius: "var(--radius)",
            }}
          />
          <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "var(--text-tertiary)", fontSize: 13 }}>
            🔍
          </span>
        </div>

        {/* AI PROVIDER SELECTOR */}
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value as any)}
          style={{ padding: "10px 8px", fontSize: 12, borderRadius: "var(--radius)", border: "1px solid var(--border-default)", background: "var(--bg-surface-muted)" }}
        >
          <option value="auto">AI: Auto / World Model</option>
          <option value="groq">AI: Groq (Llama-3.3)</option>
          <option value="gemini">AI: Gemini 2.5 Flash</option>
        </select>

        {/* API KEY SETTINGS TOGGLE */}
        <button
          type="button"
          className="btn"
          onClick={() => setShowSettings(!showSettings)}
          style={{ padding: "9px 12px", fontSize: 12 }}
          title="Configure Groq / Gemini API Key"
        >
          ⚙ Key
        </button>

        {/* SUBMIT BUTTON */}
        <button type="submit" className="btn btn-primary" disabled={loading || !urlInput.trim()} style={{ padding: "10px 18px", fontSize: 12.5, fontWeight: 700 }}>
          {loading ? "Scanning..." : "⚡ Predict Cyberattacks"}
        </button>
      </form>

      {/* OPTIONAL API KEY MODAL / DRAWER */}
      {showSettings && (
        <div
          style={{
            position: "absolute",
            top: "105%",
            right: 0,
            width: 320,
            padding: 14,
            background: "var(--bg-surface-elevated)",
            border: "1px solid var(--border-strong)",
            borderRadius: "var(--radius)",
            boxShadow: "var(--shadow-lg)",
            zIndex: 40,
          }}
        >
          <div className="flex between center" style={{ marginBottom: 8 }}>
            <span className="tag">AI PROVIDER CONFIGURATION</span>
            <button onClick={() => setShowSettings(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-tertiary)" }}>
              ✕
            </button>
          </div>
          <p className="muted" style={{ fontSize: 11, marginBottom: 10 }}>
            Enter your <b>Groq API Key</b> or <b>Gemini API Key</b> below for real-time LLM attack prediction:
          </p>
          <input
            type="password"
            className="mono"
            placeholder="gsk_... or AIza..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            style={{ width: "100%", fontSize: 11, marginBottom: 8 }}
          />
          <div className="faint" style={{ fontSize: 10 }}>
            Key is sent securely to API endpoint per request.
          </div>
        </div>
      )}

      {/* SCAN RESULT POPUP / MODAL REPORT */}
      {result && (
        <div
          style={{
            marginTop: 16,
            padding: 20,
            background: "var(--bg-surface-elevated)",
            border:
              result.status === "CRITICAL_ATTACK" || result.status === "HIGH_RISK"
                ? "1px solid var(--security-critical)"
                : "1px solid var(--border-strong)",
            borderRadius: "var(--radius)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          <div className="flex between center" style={{ marginBottom: 12, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 8 }}>
            <div>
              <span className="tag">CYBERATTACK PREDICTION REPORT</span>
              <div className="mono" style={{ fontSize: 16, fontWeight: 800, color: "var(--text-primary)", marginTop: 2 }}>
                {result.domain}
              </div>
            </div>
            <div className="flex center gap">
              <span
                className={`badge ${
                  result.status === "CRITICAL_ATTACK"
                    ? "b-crit"
                    : result.status === "HIGH_RISK"
                    ? "b-high"
                    : result.status === "ELEVATED"
                    ? "b-elev"
                    : "b-low"
                }`}
                style={{ padding: "5px 12px", fontSize: 11 }}
              >
                <span className="dot" /> STATUS: {result.status.replace("_", " ")}
              </span>
              <button onClick={() => setResult(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-tertiary)", fontSize: 14 }}>
                ✕
              </button>
            </div>
          </div>

          <div className="grid cols-3 gap" style={{ marginBottom: 16 }}>
            <div>
              <span className="tag">ATTACK PROBABILITY</span>
              <div className="mono" style={{ fontSize: 26, fontWeight: 800, color: result.attackProbability > 0.6 ? "var(--security-critical)" : "var(--security-safe)" }}>
                {(result.attackProbability * 100).toFixed(0)}%
              </div>
            </div>
            <div>
              <span className="tag">PREDICTED STAGE</span>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)", marginTop: 4 }}>
                {result.predictedStage}
              </div>
            </div>
            <div>
              <span className="tag">AI ENGINE USED</span>
              <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--brand-accent)", marginTop: 4 }}>
                {result.aiProviderUsed}
              </div>
            </div>
          </div>

          <div style={{ padding: 12, background: "var(--bg-surface-muted)", borderRadius: "var(--radius)", marginBottom: 16 }}>
            <span className="tag">AI THREAT ANALYSIS SUMMARY</span>
            <p style={{ fontSize: 12.5, color: "var(--text-primary)", marginTop: 4, lineHeight: 1.5 }}>
              {result.analysisSummary}
            </p>
          </div>

          <div>
            <span className="tag" style={{ marginBottom: 8, display: "block" }}>
              OBSERVED TELEMETRY SIGNALS
            </span>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {result.signals.map((s, i) => (
                <div key={i} className="flex between center" style={{ padding: "6px 10px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: 4, fontSize: 11.5 }}>
                  <span>{s.name}</span>
                  <span className="mono" style={{ fontWeight: 700, color: s.risk === "crit" ? "var(--security-critical)" : s.risk === "warn" ? "var(--security-warning)" : "var(--security-safe)" }}>
                    {s.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
