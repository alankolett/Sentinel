"use client";

import { useState } from "react";
import { STAGE_TECHNIQUE } from "@/lib/attack";
import type { Stage } from "@/lib/types";

interface ForecastStep {
  step: number;
  topStage: string;
  infiltration: number;
  confidence: number;
}

interface ForecastTimelineProps {
  forecast: ForecastStep[];
  currentStage: string;
  predictedStage: string;
  horizonSeconds?: number;
}

interface TimelineItem {
  step: number;
  stage: string;
  infiltration: number;
  confidence: number;
  label: string;
  isObserved: boolean;
}

export function ForecastTimeline({ forecast, currentStage, predictedStage, horizonSeconds = 50 }: ForecastTimelineProps) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  // Synthesize observed history steps leading up to NOW (step 0)
  const observedHistory: TimelineItem[] = [
    { step: -3, stage: "Benign", infiltration: 0.05, confidence: 1.0, label: "T-30s", isObserved: true },
    { step: -2, stage: "Reconnaissance", infiltration: 0.22, confidence: 1.0, label: "T-20s", isObserved: true },
    { step: -1, stage: "Initial Access", infiltration: 0.48, confidence: 1.0, label: "T-10s", isObserved: true },
  ];

  const predictedFuture: TimelineItem[] = forecast.map((f) => ({
    step: f.step,
    stage: f.topStage,
    infiltration: f.infiltration,
    confidence: f.confidence,
    label: f.step === 0 ? "NOW" : `T+${f.step * 10}s`,
    isObserved: false,
  }));

  const timelineSteps: TimelineItem[] = [...observedHistory, ...predictedFuture];

  const getStageColor = (stage: string) => {
    if (stage === "Benign") return "var(--security-safe)";
    if (/Exfil|Command|Lateral/.test(stage)) return "var(--security-critical)";
    if (/Access|Credential|Escalation/.test(stage)) return "var(--security-high)";
    return "var(--security-warning)";
  };

  return (
    <div className="forecast-timeline-container" style={{ width: "100%", overflowX: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div className="flex center gap">
          <span className="tag">ATTACK PROGRESSION TIMELINE</span>
          <span className="pill" style={{ fontSize: 10 }}>P(Sₜ₊ₖ|Sₜ) Rollout</span>
        </div>
        <div className="legend" style={{ fontSize: 10 }}>
          <span><i style={{ background: "var(--brand-primary)", height: 8, width: 8, borderRadius: "50%" }} /> Observed (Solid)</span>
          <span><i style={{ background: "var(--security-high)", height: 8, width: 8, borderRadius: "50%", border: "1px dashed var(--security-high)" }} /> Forecast Horizon ({horizonSeconds}s)</span>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, minWidth: 680, padding: "12px 4px", position: "relative" }}>
        {timelineSteps.map((s, idx) => {
          const isNow = s.label === "NOW";
          const isHovered = hoveredIdx === idx;
          const stageColor = getStageColor(s.stage);
          const technique = STAGE_TECHNIQUE[s.stage as Stage] || "T1059 — Command Scripting";
          const isObserved = s.isObserved;

          return (
            <div
              key={idx}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              style={{
                flex: 1,
                position: "relative",
                padding: "12px 10px",
                borderRadius: "var(--radius)",
                background: isNow
                  ? "color-mix(in srgb, var(--brand-accent) 8%, var(--bg-surface))"
                  : isObserved
                  ? "var(--bg-surface-muted)"
                  : "var(--bg-surface)",
                border: isNow
                  ? "2px solid var(--brand-accent)"
                  : isObserved
                  ? "1px solid var(--border-default)"
                  : "1px dashed var(--border-strong)",
                transition: "all var(--motion-fast)",
                cursor: "pointer",
                boxShadow: isHovered ? "var(--shadow-md)" : "none",
                transform: isHovered ? "translateY(-2px)" : "none",
              }}
            >
              {/* NOW Vertical Marker Pin */}
              {isNow && (
                <div
                  style={{
                    position: "absolute",
                    top: -10,
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: "var(--brand-accent)",
                    color: "#ffffff",
                    fontSize: 9,
                    fontWeight: 700,
                    padding: "1px 6px",
                    borderRadius: 3,
                    fontFamily: "var(--mono)",
                    letterSpacing: "0.1em",
                  }}
                >
                  NOW
                </div>
              )}

              {/* Time Label */}
              <div className="mono" style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-tertiary)", textAlign: "center", marginBottom: 6 }}>
                {s.label}
              </div>

              {/* Stage Title */}
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 650,
                  color: stageColor,
                  textAlign: "center",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  marginBottom: 6,
                }}
              >
                {s.stage}
              </div>

              {/* Probability Meter Bar */}
              <div className="bar-track" style={{ height: 5, marginBottom: 8 }}>
                <div
                  className="bar-fill"
                  style={{
                    width: `${Math.round(s.infiltration * 100)}%`,
                    background: stageColor,
                    opacity: isObserved ? 1 : 0.8,
                  }}
                />
              </div>

              {/* Probability & Confidence Numbers */}
              <div className="flex between center mono" style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                <span>{(s.infiltration * 100).toFixed(0)}%</span>
                <span className="muted" style={{ fontSize: 9 }}>
                  {s.confidence ? `c:${(s.confidence * 100).toFixed(0)}%` : "hist"}
                </span>
              </div>

              {/* Mapped MITRE ID */}
              <div
                className="mono faint"
                style={{
                  fontSize: 9.5,
                  marginTop: 6,
                  textAlign: "center",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {technique.split(" ")[0]}
              </div>

              {/* Rich Hover Tooltip */}
              {isHovered && (
                <div
                  style={{
                    position: "absolute",
                    bottom: "105%",
                    left: "50%",
                    transform: "translateX(-50%)",
                    width: 210,
                    padding: "10px 12px",
                    background: "var(--bg-surface-elevated)",
                    border: "1px solid var(--border-default)",
                    borderRadius: "var(--radius)",
                    boxShadow: "var(--shadow-lg)",
                    zIndex: 50,
                    pointerEvents: "none",
                  }}
                >
                  <div className="flex between center" style={{ borderBottom: "1px solid var(--border-subtle)", paddingBottom: 4, marginBottom: 6 }}>
                    <span className="mono" style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: 11 }}>
                      {s.label}
                    </span>
                    <span className={`badge ${s.isObserved ? "b-info" : "b-high"}`} style={{ fontSize: 8.5 }}>
                      {s.isObserved ? "OBSERVED STATE" : "PREDICTED STATE"}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <span className="muted">Attack Stage: </span>
                    <b style={{ color: stageColor }}>{s.stage}</b>
                  </div>
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <span className="muted">Infiltration Probability: </span>
                    <b className="mono">{(s.infiltration * 100).toFixed(1)}%</b>
                  </div>
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <span className="muted">World Model Confidence: </span>
                    <b className="mono">{(s.confidence * 100).toFixed(1)}%</b>
                  </div>
                  <div className="mono faint" style={{ fontSize: 10, marginTop: 4, paddingTop: 4, borderTop: "1px stroke var(--border-subtle)" }}>
                    Technique: {technique}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
