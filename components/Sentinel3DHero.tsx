"use client";

import { useEffect, useRef, useState } from "react";

export function Sentinel3DHero() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [isDark, setIsDark] = useState(true);

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
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 520);
    let height = (canvas.height = 420);

    let targetRotX = 0;
    let targetRotY = 0;
    let rotX = 0;
    let rotY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left - width / 2;
      const y = e.clientY - rect.top - height / 2;
      targetRotY = (x / width) * 0.8;
      targetRotX = (-y / height) * 0.8;
    };

    window.addEventListener("mousemove", handleMouseMove);

    const handleResize = () => {
      if (!canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = 420;
    };
    window.addEventListener("resize", handleResize);

    const numPoints = 120;
    const points: { x: number; y: number; z: number; baseR: number; speed: number; phase: number }[] = [];
    const radius = 130;

    for (let i = 0; i < numPoints; i++) {
      const theta = Math.acos(2 * Math.random() - 1);
      const phi = 2 * Math.PI * Math.random();
      points.push({
        x: radius * Math.sin(theta) * Math.cos(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(theta),
        baseR: radius,
        speed: 0.002 + Math.random() * 0.003,
        phase: Math.random() * Math.PI * 2,
      });
    }

    let angle = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      rotX += (targetRotX - rotX) * 0.05;
      rotY += (targetRotY - rotY) * 0.05;

      angle += 0.008;

      const cx = width / 2;
      const cy = height / 2;

      // Draw background ambient glow adaptively
      const grad = ctx.createRadialGradient(cx, cy, 10, cx, cy, 220);
      if (isDark) {
        grad.addColorStop(0, "rgba(59, 130, 246, 0.15)");
        grad.addColorStop(0.5, "rgba(37, 99, 235, 0.05)");
        grad.addColorStop(1, "rgba(0, 0, 0, 0)");
      } else {
        grad.addColorStop(0, "rgba(37, 99, 235, 0.1)");
        grad.addColorStop(0.5, "rgba(244, 242, 236, 0.3)");
        grad.addColorStop(1, "rgba(255, 255, 255, 0)");
      }
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, width, height);

      // Project 3D points
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

        const fov = 350;
        const scale = fov / (fov + z3 + 180);
        const px = cx + x2 * scale;
        const py = cy + y3 * scale;
        const alpha = Math.max(0.15, (z3 + radius) / (radius * 2));

        projected.push({ x: px, y: py, z: z3, alpha });
      });

      // Draw 3D Connecting Edges
      ctx.lineWidth = 0.9;
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const p1 = projected[i];
          const p2 = projected[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 54) {
            const edgeAlpha = (1 - dist / 54) * (isDark ? 0.35 : 0.45) * Math.min(p1.alpha, p2.alpha);
            ctx.strokeStyle = isDark ? `rgba(59, 130, 246, ${edgeAlpha})` : `rgba(15, 23, 42, ${edgeAlpha * 1.2})`;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }

      // Draw 3D Orbiting Rings
      const rings = [160, 190];
      rings.forEach((ringR, rIdx) => {
        ctx.beginPath();
        if (isDark) {
          ctx.strokeStyle = rIdx === 0 ? "rgba(249, 115, 22, 0.4)" : "rgba(59, 130, 246, 0.3)";
        } else {
          ctx.strokeStyle = rIdx === 0 ? "rgba(234, 88, 12, 0.6)" : "rgba(37, 99, 235, 0.5)";
        }
        ctx.lineWidth = 1.2;
        if (rIdx === 0) ctx.setLineDash([6, 6]);
        else ctx.setLineDash([]);

        for (let a = 0; a <= Math.PI * 2; a += 0.1) {
          const rx = ringR * Math.cos(a + angle * (rIdx === 0 ? 1 : -0.7));
          const ry = ringR * Math.sin(a + angle * (rIdx === 0 ? 1 : -0.7)) * 0.35;
          const rz = ringR * Math.sin(a);

          const scale = 350 / (350 + rz + 180);
          const px = cx + rx * scale;
          const py = cy + ry * scale;

          if (a === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // Draw Nodes
      projected.forEach((p) => {
        const nodeR = 2.8 * (350 / (350 + p.z + 180));
        if (isDark) {
          ctx.fillStyle = p.z > 40 ? `rgba(239, 68, 68, ${p.alpha})` : `rgba(59, 130, 246, ${p.alpha})`;
        } else {
          ctx.fillStyle = p.z > 40 ? `rgba(220, 38, 38, ${p.alpha})` : `rgba(37, 99, 235, ${p.alpha})`;
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, Math.max(1.2, nodeR), 0, Math.PI * 2);
        ctx.fill();
      });

      // Center Core
      ctx.fillStyle = isDark ? "rgba(59, 130, 246, 0.9)" : "rgba(37, 99, 235, 0.95)";
      ctx.beginPath();
      ctx.arc(cx, cy, 6 + Math.sin(angle * 3) * 2, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = isDark ? "rgba(255, 255, 255, 0.7)" : "rgba(15, 23, 42, 0.8)";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(cx, cy, 14 + Math.sin(angle * 2) * 3, 0, Math.PI * 2);
      ctx.stroke();

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("resize", handleResize);
    };
  }, [isDark]);

  return (
    <div
      className="sentinel-3d-wrap"
      style={{
        position: "relative",
        width: "100%",
        height: 420,
        background: isDark ? "rgba(15, 21, 36, 0.65)" : "var(--bg-surface)",
        borderRadius: "var(--radius)",
        border: isDark ? "1px solid var(--border-default)" : "1px solid var(--border-default)",
      }}
    >
      <canvas ref={canvasRef} style={{ width: "100%", height: "100%", display: "block" }} />

      {/* Floating HUD Overlay Badges */}
      <div
        style={{
          position: "absolute",
          top: 20,
          left: 20,
          padding: "8px 12px",
          background: isDark ? "rgba(15, 21, 36, 0.85)" : "rgba(255, 255, 255, 0.92)",
          backdropFilter: "blur(8px)",
          border: isDark ? "1px solid var(--border-default)" : "1px solid var(--border-default)",
          borderRadius: "var(--radius)",
          fontSize: 11,
          boxShadow: "var(--shadow-md)",
        }}
      >
        <div className="flex center gap" style={{ marginBottom: 4 }}>
          <span className="dot" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--security-safe)" }} />
          <span className="mono" style={{ fontWeight: 700, color: "var(--text-primary)" }}>
            SENTINEL 3D WORLD MODEL
          </span>
        </div>
        <div style={{ fontSize: 10, color: "var(--text-secondary)" }}>
          Interactive P(Sₜ₊₁|Sₜ) Latent Space Mesh
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          bottom: 20,
          right: 20,
          padding: "8px 12px",
          background: isDark ? "rgba(15, 21, 36, 0.85)" : "rgba(255, 255, 255, 0.92)",
          backdropFilter: "blur(8px)",
          border: "1px solid var(--security-high)",
          borderRadius: "var(--radius)",
          fontSize: 11,
          boxShadow: isDark ? "0 0 16px rgba(249, 115, 22, 0.2)" : "var(--shadow-md)",
        }}
      >
        <div className="flex between center gap">
          <span className="tag" style={{ color: "var(--security-high)" }}>PREDICTED LATERAL MOVEMENT</span>
          <span className="mono" style={{ color: "var(--security-high)", fontWeight: 700 }}>82% PROB</span>
        </div>
      </div>
    </div>
  );
}
