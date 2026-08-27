"use client";

import { useEffect, useRef, useState } from "react";
import type { ReactNode, CSSProperties } from "react";

export function useCountUp(target: number, ms = 900): number {
  const [v, setV] = useState(0);
  const raf = useRef(0);

  useEffect(() => {
    if (typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setV(target);
      return;
    }
    const t0 = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      setV(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target, ms]);

  return v;
}

export function CountUp({ value, decimals = 0, prefix = "", suffix = "" }: { value: number; decimals?: number; prefix?: string; suffix?: string }) {
  const v = useCountUp(value);
  return (
    <>
      {prefix}
      {v.toFixed(decimals)}
      {suffix}
    </>
  );
}

const C = {
  brand: "var(--brand-accent)",
  brand2: "var(--brand-primary)",
  warn: "var(--security-warning)",
  high: "var(--security-high)",
  ok: "var(--security-safe)",
  crit: "var(--security-critical)",
  grid: "var(--border-subtle)",
  axis: "var(--border-default)",
  text: "var(--text-tertiary)",
  muted: "var(--text-tertiary)",
};

interface Series {
  label: string;
  color: string;
  points: number[];
  dashed?: boolean;
}

export function LineChart({
  series,
  height = 220,
  yMax = 1,
  markers = [],
  xLabels,
}: {
  series: Series[];
  height?: number;
  yMax?: number;
  markers?: { x: number; label: string; color: string }[];
  xLabels?: string[];
}) {
  const W = 720, H = height, pad = { l: 38, r: 16, t: 14, b: 24 };
  const n = Math.max(...series.map((s) => s.points.length), 1);
  const px = (i: number) => pad.l + (i / Math.max(1, n - 1)) * (W - pad.l - pad.r);
  const py = (v: number) => pad.t + (1 - Math.min(v, yMax) / yMax) * (H - pad.t - pad.b);
  const gridY = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: "block", minWidth: 480 }} role="img">
        {gridY.map((g, i) => (
          <g key={i}>
            <line x1={pad.l} x2={W - pad.r} y1={py(g)} y2={py(g)} stroke={C.grid} />
            <text x={pad.l - 6} y={py(g) + 3} textAnchor="end" fontSize="9" fill={C.text} className="mono">
              {g.toFixed(2)}
            </text>
          </g>
        ))}
        {markers.map((m, i) => (
          <g key={i}>
            <line x1={px(m.x)} x2={px(m.x)} y1={pad.t} y2={H - pad.b} stroke={m.color} strokeDasharray="3 3" opacity="0.85" />
            <text x={px(m.x) + 3} y={pad.t + 9} fontSize="9" fill={m.color} fontWeight="700" className="mono">
              {m.label}
            </text>
          </g>
        ))}
        {series.map((s, si) => {
          const d = s.points.map((v, i) => `${i === 0 ? "M" : "L"} ${px(i).toFixed(1)} ${py(v).toFixed(1)}`).join(" ");
          const area = `${d} L ${px(s.points.length - 1)} ${py(0)} L ${px(0)} ${py(0)} Z`;
          const grad = `grad-${si}-${Math.round(pad.l)}`;

          return (
            <g key={si}>
              {!s.dashed && (
                <>
                  <defs>
                    <linearGradient id={grad} x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor={s.color} stopOpacity="0.12" />
                      <stop offset="100%" stopColor={s.color} stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  <path d={area} fill={`url(#${grad})`} style={{ animation: "fade .8s var(--ease) both" }} />
                </>
              )}
              <path
                d={d}
                fill="none"
                stroke={s.color}
                strokeWidth="2"
                strokeDasharray={s.dashed ? "5 4" : undefined}
                strokeLinejoin="round"
                strokeLinecap="round"
                style={s.dashed ? undefined : ({ ["--len"]: 2600, animation: "drawLine 1.2s var(--ease) both" } as CSSProperties)}
              />
            </g>
          );
        })}
        {xLabels &&
          xLabels.map((l, i) => (
            <text key={i} x={px(i)} y={H - 8} textAnchor="middle" fontSize="9" fill={C.text} className="mono">
              {l}
            </text>
          ))}
      </svg>
    </div>
  );
}

export function Gauge({ value, size = 150, label, sublabel }: { value: number; size?: number; label?: string; sublabel?: string }) {
  const r = size / 2 - 12, cx = size / 2, cy = size / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, value));
  const col = pct >= 0.8 ? C.crit : pct >= 0.6 ? C.high : pct >= 0.35 ? C.warn : C.ok;

  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border-subtle)" strokeWidth="8" />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={col}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ}
          style={{ animation: "gaugeFill 1.1s var(--ease) forwards", ["--goff" as string]: circ * (1 - pct) } as CSSProperties}
        />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
        <div>
          <div style={{ fontSize: 30, fontWeight: 700, color: col, fontVariantNumeric: "tabular-nums", lineHeight: 1 }} className="mono">
            {(pct * 100).toFixed(0)}
            <span style={{ fontSize: 14 }}>%</span>
          </div>
          {label && <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 4, fontWeight: 500 }}>{label}</div>}
          {sublabel && <div style={{ fontSize: 10, color: "var(--text-tertiary)", marginTop: 1 }} className="mono">{sublabel}</div>}
        </div>
      </div>
    </div>
  );
}

export function BarList({ items, signed = false }: { items: { label: string; value: number; hint?: string }[]; signed?: boolean }) {
  const max = Math.max(...items.map((i) => Math.abs(i.value)), 1e-6);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {items.map((it, i) => {
        const w = (Math.abs(it.value) / max) * 100;
        const pos = it.value >= 0;
        const col = signed ? (pos ? C.high : C.ok) : C.brand;

        return (
          <div key={i}>
            <div className="flex between" style={{ fontSize: 12, marginBottom: 4 }}>
              <span className="mono" style={{ color: "var(--text-primary)" }}>{it.label}</span>
              <span style={{ color: col, fontWeight: 700, fontVariantNumeric: "tabular-nums" }} className="mono">
                {signed && pos ? "+" : ""}
                {(it.value * 100).toFixed(1)}%
              </span>
            </div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${w}%`, background: col }} />
            </div>
            {it.hint && <div className="faint" style={{ fontSize: 10.5, marginTop: 2 }}>{it.hint}</div>}
          </div>
        );
      })}
    </div>
  );
}

export function ConfusionMatrix({ tp, fp, tn, fn, title }: { tp: number; fp: number; tn: number; fn: number; title: string }) {
  const cell = (v: number, good: boolean, lbl: string) => (
    <div style={{ padding: "16px 8px", textAlign: "center", background: good ? "var(--security-safe-bg)" : "var(--security-critical-bg)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)" }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: good ? C.ok : C.crit }} className="mono">{v}</div>
      <div className="faint" style={{ fontSize: 10.5, marginTop: 2 }}>{lbl}</div>
    </div>
  );
  return (
    <div>
      <div className="tag" style={{ marginBottom: 8 }}>{title}</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {cell(tp, true, "True Positive")}{cell(fp, false, "False Positive")}
        {cell(fn, false, "False Negative")}{cell(tn, true, "True Negative")}
      </div>
    </div>
  );
}

export function RocCurve({ curves }: { curves: { label: string; color: string; scores: number[]; labels: number[] }[] }) {
  const W = 300, H = 300, pad = 34;
  const px = (v: number) => pad + v * (W - pad - 12);
  const py = (v: number) => (H - pad) - v * (H - pad - 12);
  const roc = (scores: number[], labels: number[]): [number, number][] => {
    const pairs = scores.map((s, i) => ({ s, y: labels[i] })).sort((a, b) => b.s - a.s);
    const totP = labels.filter((l) => l === 1).length || 1, totN = labels.filter((l) => l === 0).length || 1;
    const pts: [number, number][] = [[0, 0]]; let tp = 0, fp = 0;
    for (const p of pairs) { if (p.y === 1) tp++; else fp++; pts.push([fp / totN, tp / totP]); }
    return pts;
  };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: 300 }}>
      <line x1={pad} y1={py(0)} x2={px(1)} y2={py(0)} stroke={C.axis} />
      <line x1={pad} y1={py(0)} x2={pad} y2={py(1)} stroke={C.axis} />
      <line x1={pad} y1={py(0)} x2={px(1)} y2={py(1)} stroke={C.axis} strokeDasharray="4 4" opacity="0.7" />
      <text x={W / 2} y={H - 6} textAnchor="middle" fontSize="9" fill={C.text} className="mono">False Positive Rate</text>
      <text x={10} y={H / 2} textAnchor="middle" fontSize="9" fill={C.text} transform={`rotate(-90 10 ${H / 2})`} className="mono">True Positive Rate</text>
      {curves.map((c, ci) => {
        const pts = roc(c.scores, c.labels);
        const d = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${px(p[0]).toFixed(1)} ${py(p[1]).toFixed(1)}`).join(" ");
        return <path key={ci} d={d} fill="none" stroke={c.color} strokeWidth="2" />;
      })}
    </svg>
  );
}

export function Panel({ title, children, right, accent }: { title?: string; children: ReactNode; right?: ReactNode; accent?: boolean }) {
  return (
    <div className="card">
      {accent && <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: "var(--brand-accent)" }} />}
      {title && (
        <div className="flex between center" style={{ marginBottom: 14 }}>
          <h3>{title}</h3>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export const COLORS = C;
