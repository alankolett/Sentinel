"use client";

import { useMemo } from "react";
import { useStore } from "@/lib/store";
import { Topbar, NeedData } from "@/components/shell";
import { LineChart, Panel, COLORS } from "@/components/charts";
import { FEATURES } from "@/lib/types";

export default function DatasetPage() {
  const { result, source, loadDatasetPreset } = useStore();

  const stats = useMemo(() => {
    if (!result) return null;
    const w = result.windows;
    const mal = w.filter((x) => x.malicious).length;
    // per-window malicious ratio timeline & flow counts
    const flowSeries = w.map((x) => x.flowCount);
    const malSeries = w.map((x) => (x.malicious ? 1 : 0));
    // feature means (benign vs malicious) for the distribution table
    const rows = FEATURES.map((f, j) => {
      const benign = w.filter((x) => !x.malicious).map((x) => x.vec[j]);
      const attack = w.filter((x) => x.malicious).map((x) => x.vec[j]);
      return { f, benign: mean(benign), attack: mean(attack) };
    });
    return { windows: w.length, mal, benign: w.length - mal, flowSeries, malSeries, rows, maxFlow: Math.max(...flowSeries, 1) };
  }, [result]);

  if (!result || !stats) return (<><Topbar title="Dataset Explorer" sub="Distributions & temporal structure" /><NeedData /></>);
  const r = result;

  const datasets = [
    { name: "CSE-CIC-IDS2018", label: "CSE-CIC-IDS2018 (Infiltration Day)" },
    { name: "CIC-IDS2017", label: "CIC-IDS2017 (DDoS & Web Attacks)" },
    { name: "UNSW-NB15", label: "UNSW-NB15 (Fuzzers & Exploits)" },
    { name: "CTU-13", label: "CTU-13 (Botnet C&C Traffic)" },
  ];

  const currentDataset = datasets.find((d) => source?.includes(d.name))?.name || "CSE-CIC-IDS2018";

  return (
    <>
      <Topbar title="Dataset Explorer" sub="Capture statistics, attack distribution & temporal windows" />

      {/* Dataset Selector Bar */}
      <div
        className="card"
        style={{
          marginBottom: 16,
          padding: "12px 18px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 12,
          border: "1px solid var(--brand-accent)",
          background: "rgba(59, 130, 246, 0.04)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 13, fontWeight: 700, fontFamily: "var(--sans)", color: "var(--text-primary)" }}>
            📊 ACTIVE DATASET PRESET:
          </span>
          <span className="badge b-high" style={{ fontFamily: "var(--sans)", fontWeight: 700 }}>
            {currentDataset}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {datasets.map((d) => (
            <button
              key={d.name}
              onClick={() => loadDatasetPreset(d.name)}
              style={{
                padding: "6px 14px",
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 700,
                fontFamily: "var(--sans)",
                cursor: "pointer",
                border: currentDataset === d.name ? "1.5px solid var(--brand-accent)" : "1px solid var(--border-default)",
                background: currentDataset === d.name ? "var(--brand-accent)" : "var(--bg-surface)",
                color: currentDataset === d.name ? "#ffffff" : "var(--text-secondary)",
                transition: "all 0.2s ease",
              }}
            >
              {d.name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid cols-4">
        <Kpi label="Flows" v={r.meta.flows.toLocaleString()} />
        <Kpi label="Temporal windows" v={String(stats.windows)} />
        <Kpi label="Malicious windows" v={`${stats.mal} (${((stats.mal / stats.windows) * 100).toFixed(0)}%)`} color={COLORS.high} />
        <Kpi label="Latent states (k)" v={String(r.model.cluster.k)} />
      </div>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <Panel title="Flow Volume per Window">
          <LineChart height={190} yMax={stats.maxFlow} series={[{ label: "flows", color: COLORS.brand, points: stats.flowSeries }]} />
        </Panel>
        <Panel title="Attack Label Timeline">
          <LineChart height={190} yMax={1} series={[{ label: "malicious", color: COLORS.high, points: stats.malSeries }]} />
          <div className="legend" style={{ marginTop: 6 }}><span className="faint">1 = window contains labelled attack traffic · 0 = benign</span></div>
        </Panel>
      </div>

      <div className="section-title">Latent State Distribution</div>
      <div className="card">
        <table>
          <thead><tr><th>State</th><th>Windows</th><th>Mapped stage</th><th>Infiltration score</th></tr></thead>
          <tbody>
            {r.model.cluster.stage.map((s, c) => (
              <tr key={c}>
                <td className="mono">S{c}</td>
                <td>{r.model.cluster.sizes[c]}</td>
                <td style={{ fontWeight: 600 }}>{s}</td>
                <td>
                  <div className="flex center gap">
                    <div className="bar-track" style={{ width: 120 }}><div className="bar-fill" style={{ width: `${r.model.cluster.infiltration[c] * 100}%`, background: r.model.cluster.infiltration[c] > 0.5 ? COLORS.high : COLORS.brand }} /></div>
                    <span className="mono">{(r.model.cluster.infiltration[c] * 100).toFixed(0)}%</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="section-title">Feature Distribution — Benign vs Malicious</div>
      <div className="card">
        <table>
          <thead><tr><th>Feature</th><th>Benign mean</th><th>Malicious mean</th><th>Separation</th></tr></thead>
          <tbody>
            {stats.rows.map((row) => {
              const sep = row.attack - row.benign;
              const rel = row.benign !== 0 ? sep / Math.abs(row.benign) : sep;
              return (
                <tr key={row.f}>
                  <td className="mono">{row.f}</td>
                  <td>{fmt(row.benign)}</td>
                  <td style={{ color: COLORS.high }}>{fmt(row.attack)}</td>
                  <td><span className={`badge ${Math.abs(rel) > 0.5 ? "b-high" : Math.abs(rel) > 0.1 ? "b-elev" : "b-low"}`}>{rel >= 0 ? "+" : ""}{(rel * 100).toFixed(0)}%</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

const mean = (a: number[]): number => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
const fmt = (v: number): string => (Math.abs(v) >= 1000 ? v.toExponential(1) : Math.abs(v) >= 1 ? v.toFixed(1) : v.toFixed(3));

function Kpi({ label, v, color }: { label: string; v: string; color?: string }) {
  return (<div className="card"><div className="stat"><span className="tag">{label}</span><div className="val" style={{ color: color ?? "var(--text)" }}>{v}</div></div></div>);
}
