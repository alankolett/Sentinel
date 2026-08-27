"use client";

import { useEffect, useState, useRef } from "react";

export function IntroAnimation() {
  const [visible, setVisible] = useState(true);
  const [fadeOut, setFadeOut] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logIndex, setLogIndex] = useState(0);
  const [isDark, setIsDark] = useState(true);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const logs = [
    "Loading CIC-IDS2018 World Model Weights...",
    "Initializing P(Sₜ₊₁|Sₜ) Latent Transition Space...",
    "Calibrating 79 Flow Feature Extraction Pipelines...",
    "Mapping MITRE ATT&CK Telemetry Matrix...",
    "Sentinel Cyber Defense Operational.",
  ];

  const pipelineSteps = [
    { num: "01", title: "Traffic Ingestion", sub: "PCAP / NetFlow" },
    { num: "02", title: "Feature Extract", sub: "79 Flow Features" },
    { num: "03", title: "Temporal State", sub: "Sequential Windows" },
    { num: "04", title: "LSTM Model", sub: "Learned Latent Space" },
    { num: "05", title: "K-Step Rollout", sub: "Forward Forecast" },
    { num: "06", title: "Explainability", sub: "Feature Attribution" },
    { num: "07", title: "MITRE ATT&CK", sub: "Technique Mapping" },
    { num: "08", title: "Defender Action", sub: "SOC Playbooks" },
  ];

  // Theme observer matching app data-theme
  useEffect(() => {
    const updateTheme = () => {
      const t = document.documentElement.getAttribute("data-theme");
      setIsDark(t === "dark");
    };

    updateTheme();

    const observer = new MutationObserver(updateTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    // Smooth progress counter (~6 seconds total)
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          return 100;
        }
        return prev + 0.75;
      });
    }, 40);

    // Telemetry log updates
    const logInterval = setInterval(() => {
      setLogIndex((prev) => (prev < logs.length - 1 ? prev + 1 : prev));
    }, 1200);

    // Complete boot after ~6.8 seconds
    const timer = setTimeout(() => {
      completeBoot();
    }, 6800);

    return () => {
      clearInterval(progressInterval);
      clearInterval(logInterval);
      clearTimeout(timer);
    };
  }, []);

  const completeBoot = () => {
    setFadeOut(true);
    setTimeout(() => {
      setVisible(false);
    }, 500);
  };

  // Calculate active step index (0 to 7) based on progress
  const activeStepIndex = Math.min(7, Math.floor((progress / 100) * 8));

  // ---------------------------------------------------------------------------
  // 3D Canvas Engine: Sleek Interactive Sentinel Telemetry Mesh
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!visible) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let W = (canvas.width = 320);
    let H = (canvas.height = 320);

    let targetRotX = 0;
    let targetRotY = 0;
    let rotX = 0.1;
    let rotY = 0.2;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left - W / 2;
      const y = e.clientY - rect.top - H / 2;
      targetRotY = (x / W) * 0.6;
      targetRotX = (-y / H) * 0.6;
    };
    window.addEventListener("mousemove", handleMouseMove);

    // 3D Point Sphere Generator
    const numPoints = 90;
    const radius = 95;
    const points: { x: number; y: number; z: number }[] = [];

    for (let i = 0; i < numPoints; i++) {
      const theta = Math.acos(2 * Math.random() - 1);
      const phi = 2 * Math.PI * Math.random();
      points.push({
        x: radius * Math.sin(theta) * Math.cos(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(theta),
      });
    }

    let angle = 0;

    const render = () => {
      ctx.clearRect(0, 0, W, H);

      rotX += (targetRotX - rotX) * 0.05;
      rotY += (targetRotY - rotY) * 0.05;
      angle += 0.008;

      const cx = W / 2;
      const cy = H / 2;

      // Ambient Soft Glow Radial Backdrop
      const ambientGrad = ctx.createRadialGradient(cx, cy, 10, cx, cy, 150);
      if (isDark) {
        ambientGrad.addColorStop(0, "rgba(59, 130, 246, 0.18)");
        ambientGrad.addColorStop(0.5, "rgba(37, 99, 235, 0.05)");
        ambientGrad.addColorStop(1, "rgba(0, 0, 0, 0)");
      } else {
        ambientGrad.addColorStop(0, "rgba(37, 99, 235, 0.12)");
        ambientGrad.addColorStop(0.5, "rgba(244, 242, 236, 0.4)");
        ambientGrad.addColorStop(1, "rgba(255, 255, 255, 0)");
      }
      ctx.fillStyle = ambientGrad;
      ctx.fillRect(0, 0, W, H);

      // Project 3D points onto 2D viewport
      const projected: { x: number; y: number; z: number; alpha: number }[] = [];

      points.forEach((p) => {
        let x1 = p.x * Math.cos(angle) - p.z * Math.sin(angle);
        let z1 = p.x * Math.sin(angle) + p.z * Math.cos(angle);
        let y1 = p.y;

        const cosX = Math.cos(rotX);
        const sinX = Math.sin(rotX);
        const cosY = Math.cos(rotY);
        const sinY = Math.sin(rotY);

        let x2 = x1 * cosY - z1 * sinY;
        let z2 = x1 * sinY + z1 * cosY;

        let y3 = y1 * cosX - z2 * sinX;
        let z3 = y1 * sinX + z2 * cosX;

        const fov = 300;
        const scale = fov / (fov + z3 + 140);
        const px = cx + x2 * scale;
        const py = cy + y3 * scale;
        const alpha = Math.max(0.2, (z3 + radius) / (radius * 2));

        projected.push({ x: px, y: py, z: z3, alpha });
      });

      // Draw 3D Connecting Wireframe Edges
      ctx.lineWidth = 0.9;
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const p1 = projected[i];
          const p2 = projected[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 46) {
            const edgeAlpha = (1 - dist / 46) * (isDark ? 0.38 : 0.5) * Math.min(p1.alpha, p2.alpha);
            ctx.strokeStyle = isDark
              ? `rgba(59, 130, 246, ${edgeAlpha})`
              : `rgba(37, 99, 235, ${edgeAlpha * 1.1})`;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }

      // Draw Orbiting Rings
      ctx.beginPath();
      ctx.strokeStyle = isDark ? "rgba(59, 130, 246, 0.5)" : "rgba(37, 99, 235, 0.6)";
      ctx.lineWidth = 1.4;
      ctx.setLineDash([6, 6]);

      const ringR = 125;
      for (let a = 0; a <= Math.PI * 2; a += 0.1) {
        const rx = ringR * Math.cos(a + angle * 1.2);
        const ry = ringR * Math.sin(a + angle * 1.2) * 0.35;
        const rz = ringR * Math.sin(a);

        const scale = 300 / (300 + rz + 140);
        const px = cx + rx * scale;
        const py = cy + ry * scale;

        if (a === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.stroke();
      ctx.setLineDash([]);

      // Draw 3D Particle Nodes
      projected.forEach((p) => {
        const nodeR = 2.5 * (300 / (300 + p.z + 140));
        ctx.fillStyle = isDark
          ? p.z > 30 ? `rgba(249, 115, 22, ${p.alpha})` : `rgba(59, 130, 246, ${p.alpha})`
          : p.z > 30 ? `rgba(225, 29, 72, ${p.alpha})` : `rgba(37, 99, 235, ${p.alpha})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, Math.max(1.5, nodeR), 0, Math.PI * 2);
        ctx.fill();
      });

      // Central Core Pulse Node
      ctx.fillStyle = isDark ? "rgba(59, 130, 246, 0.95)" : "rgba(37, 99, 235, 0.95)";
      ctx.beginPath();
      ctx.arc(cx, cy, 6 + Math.sin(angle * 3) * 2, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = isDark ? "rgba(255, 255, 255, 0.85)" : "rgba(15, 23, 42, 0.85)";
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.arc(cx, cy, 14 + Math.sin(angle * 2) * 3, 0, Math.PI * 2);
      ctx.stroke();

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, [visible, isDark]);

  if (!visible) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "var(--bg-canvas)",
        color: "var(--text-primary)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 99999,
        transition: "opacity 0.5s ease, transform 0.5s ease",
        opacity: fadeOut ? 0 : 1,
        transform: fadeOut ? "scale(1.02)" : "scale(1)",
        pointerEvents: fadeOut ? "none" : "auto",
        fontFamily: "var(--sans)",
        padding: "20px 40px",
      }}
    >
      {/* Top Header Controls */}
      <div
        style={{
          position: "absolute",
          top: 24,
          left: 40,
          right: 40,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          zIndex: 10,
        }}
      >
        {/* Brand Logo & Name */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <img
            src="/sentinel-logo.jpg"
            alt="Sentinel Logo"
            style={{
              width: 34,
              height: 34,
              borderRadius: 8,
              objectFit: "cover",
              boxShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
            }}
          />
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ fontSize: 16, fontWeight: 800, letterSpacing: "-0.02em", color: "var(--text-primary)" }}>
                SENTINEL
              </div>
              <span
                style={{
                  fontSize: 9.5,
                  fontWeight: 700,
                  fontFamily: "var(--sans)",
                  color: "#2563eb",
                  background: "rgba(37, 99, 235, 0.12)",
                  padding: "1px 6px",
                  borderRadius: 4,
                  border: "1px solid rgba(37, 99, 235, 0.2)",
                }}
              >
                v4.2
              </span>
            </div>
            <div style={{ fontSize: 9.5, fontWeight: 600, fontFamily: "var(--sans)", color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.1em", marginTop: 1 }}>
              ATTACK FORECASTING
            </div>
          </div>
        </div>

        {/* Skip Button */}
        <button
          onClick={completeBoot}
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            color: "var(--text-secondary)",
            padding: "8px 18px",
            borderRadius: "var(--radius, 6px)",
            fontSize: 12.5,
            fontWeight: 600,
            cursor: "pointer",
            fontFamily: "var(--sans)",
            transition: "all 0.2s ease",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "var(--border-strong)";
            e.currentTarget.style.color = "var(--text-primary)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "var(--border-default)";
            e.currentTarget.style.color = "var(--text-secondary)";
          }}
        >
          Skip Intro →
        </button>
      </div>

      {/* Center Hero: 3D Telemetry Canvas */}
      <div style={{ position: "relative", width: 320, height: 320, marginBottom: 8 }}>
        <canvas ref={canvasRef} width={320} height={320} style={{ display: "block" }} />
      </div>

      {/* Main Title & Subtitle */}
      <div style={{ textAlign: "center", marginBottom: 20 }}>
        <h1
          style={{
            fontFamily: "var(--sans)",
            fontSize: 26,
            fontWeight: 800,
            letterSpacing: "-0.03em",
            color: "var(--text-primary)",
            marginBottom: 4,
          }}
        >
          SENTINEL
        </h1>
        <p
          style={{
            fontFamily: "var(--sans)",
            fontSize: 12,
            color: "var(--text-tertiary)",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            fontWeight: 600,
          }}
        >
          AI Network Attack Forecasting World Model
        </p>
      </div>

      {/* Progress Bar */}
      <div style={{ width: 460, maxWidth: "90vw", marginBottom: 18 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            fontSize: 12,
            fontFamily: "var(--sans)",
            color: "var(--text-secondary)",
            fontWeight: 600,
            marginBottom: 8,
          }}
        >
          <span>Initializing World Model Pipeline</span>
          <span style={{ color: "var(--brand-accent)", fontWeight: 700 }}>{Math.round(progress)}%</span>
        </div>
        <div
          style={{
            width: "100%",
            height: 5,
            background: "var(--bg-surface-muted)",
            borderRadius: 3,
            overflow: "hidden",
            border: "1px solid var(--border-subtle)",
          }}
        >
          <div
            style={{
              height: "100%",
              width: `${progress}%`,
              background: "linear-gradient(90deg, #3b82f6, #6366f1)",
              borderRadius: 3,
              transition: "width 0.04s linear",
            }}
          />
        </div>
      </div>

      {/* Telemetry Log Output */}
      <div
        style={{
          fontFamily: "var(--sans)",
          fontSize: 13,
          color: "var(--text-secondary)",
          textAlign: "center",
          height: 20,
          fontWeight: 500,
          marginBottom: 32,
        }}
      >
        {logs[logIndex]}
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* ANIMATED PROCESS FLOW PIPELINE TRANSITION ROW                          */}
      {/* --------------------------------------------------------------------- */}
      <div style={{ width: "100%", maxWidth: 1160 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "var(--text-tertiary)",
            marginBottom: 14,
            fontFamily: "var(--sans)",
            justifyContent: "center",
          }}
        >
          <span>SYSTEM PIPELINE</span>
          <span style={{ width: 28, height: 1, background: "var(--border-default)" }} />
          <span>SENTINEL WORLD MODEL ARCHITECTURE</span>
        </div>

        {/* 8-Step Pipeline Cards Strip with Animated Flow Arrows */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            width: "100%",
            gap: 2,
          }}
        >
          {pipelineSteps.map((step, idx) => {
            const isCurrent = idx === activeStepIndex;
            const isPassed = idx < activeStepIndex;

            return (
              <div key={step.num} style={{ display: "flex", alignItems: "center", flex: 1, minWidth: 0 }}>
                {/* Step Card */}
                <div
                  style={{
                    flex: 1,
                    minWidth: 0,
                    background: "var(--bg-surface)",
                    border: isCurrent
                      ? "1.5px solid var(--brand-accent)"
                      : isPassed
                      ? "1px solid var(--security-safe)"
                      : "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius, 8px)",
                    padding: "12px 6px",
                    textAlign: "center",
                    transition: "all 0.3s cubic-bezier(0.16, 1, 0.3, 1)",
                    transform: isCurrent ? "translateY(-4px)" : "none",
                    boxShadow: isCurrent
                      ? "0 6px 20px -2px rgba(59, 130, 246, 0.35)"
                      : isPassed
                      ? "0 2px 10px rgba(16, 185, 129, 0.15)"
                      : "none",
                    opacity: isCurrent ? 1 : isPassed ? 0.95 : 0.45,
                  }}
                >
                  {/* Step Number */}
                  <div
                    style={{
                      fontFamily: "var(--sans)",
                      fontSize: 11,
                      fontWeight: 800,
                      color: isCurrent
                        ? "var(--brand-accent)"
                        : isPassed
                        ? "var(--security-safe)"
                        : "var(--text-tertiary)",
                      marginBottom: 5,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: 4,
                    }}
                  >
                    <span>{step.num}</span>
                    {isPassed && <span style={{ color: "var(--security-safe)", fontSize: 10 }}>✓</span>}
                    {isCurrent && <span style={{ color: "var(--brand-accent)", fontSize: 9 }}>▶</span>}
                  </div>

                  {/* Title */}
                  <div
                    style={{
                      fontFamily: "var(--sans)",
                      fontSize: 11,
                      fontWeight: 700,
                      color: isCurrent || isPassed ? "var(--text-primary)" : "var(--text-secondary)",
                      lineHeight: 1.25,
                      marginBottom: 4,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {step.title}
                  </div>

                  {/* Subtitle */}
                  <div
                    style={{
                      fontFamily: "var(--sans)",
                      fontSize: 9,
                      fontWeight: 500,
                      color: "var(--text-tertiary)",
                      lineHeight: 1.2,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {step.sub}
                  </div>
                </div>

                {/* Animated Flow Arrow between block $i$ and block $i+1$ */}
                {idx < pipelineSteps.length - 1 && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      width: 14,
                      flexShrink: 0,
                      margin: "0 1px",
                    }}
                  >
                    <svg
                      width="12"
                      height="12"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke={
                        isPassed
                          ? "var(--security-safe)"
                          : isCurrent
                          ? "var(--brand-accent)"
                          : "var(--border-subtle)"
                      }
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      style={{
                        transition: "all 0.3s ease",
                        transform: isCurrent ? "translateX(2px) scale(1.2)" : "scale(1)",
                        filter: isCurrent
                          ? "drop-shadow(0 0 6px rgba(59, 130, 246, 0.8))"
                          : isPassed
                          ? "drop-shadow(0 0 4px rgba(16, 185, 129, 0.5))"
                          : "none",
                        opacity: isCurrent ? 1 : isPassed ? 0.85 : 0.35,
                      }}
                    >
                      <line x1="5" y1="12" x2="19" y2="12" />
                      <polyline points="12 5 19 12 12 19" />
                    </svg>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
