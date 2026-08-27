"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useStore } from "@/lib/store";
import { Topbar } from "@/components/shell";
import { Panel } from "@/components/charts";
import { demoCsv } from "@/lib/demo";

const PIPE = ["Ingest", "Schema detect", "Feature extract", "Window", "World model", "Forecast", "Explain"];
const MAX_BYTES = 25 * 1024 * 1024; // 25 MB client-side guard

export default function AnalyzePage() {
  const { analyzeFile, loadDemo, loading, error, result, schema, params, setParams, source, apiMode } = useStore();
  const [drag, setDrag] = useState(false);
  const [warn, setWarn] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const accept = apiMode ? /\.(csv|txt|tsv|pcap|pcapng)$/i : /\.(csv|txt|tsv)$/i;
  const handleFile = (file: File) => {
    setWarn(null);
    if (!accept.test(file.name)) {
      setWarn(apiMode
        ? "Allowed: .csv, .pcap, .pcapng. (PCAP needs scapy installed on the backend.)"
        : "Offline mode accepts CSV. PCAP → convert with CICFlowMeter/Zeek, or run the backend for PCAP.");
      return;
    }
    if (file.size > MAX_BYTES) { setWarn(`File too large (${(file.size / 1e6).toFixed(0)} MB). Cap is 25 MB.`); return; }
    analyzeFile(file);
    router.push("/forecast");
  };

  const downloadDemo = () => {
    const blob = new Blob([demoCsv(7)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "aegischronos_demo_capture.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Topbar title="Upload & Analyze" sub="Ingest → Parse → Feature Extraction → Windowing → World Model → Forecast → Explain" />

      <div className="grid cols-2" style={{ gridTemplateColumns: "1.4fr 1fr" }}>
        <Panel accent>
          <div
            className={`dropzone ${drag ? "drag" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
            onClick={() => inputRef.current?.click()}
            role="button" tabIndex={0}
          >
            <div style={{ fontSize: 38, marginBottom: 8 }}>⬆</div>
            <h3 style={{ textTransform: "none", color: "var(--text)", fontSize: 16 }}>Drop a flow CSV here</h3>
            <p className="muted" style={{ fontSize: 13, margin: "6px 0 0" }}>
              CIC-IDS2017/2018 · UNSW-NB15 · CTU-13 · CICIoT2023 · any NetFlow/IPFIX export
            </p>
            <p className="faint" style={{ fontSize: 12, marginTop: 4 }}>
              {apiMode ? "Sent to the local Sentinel backend for real world-model inference." : "Parsed locally in your browser — nothing is uploaded."}
            </p>
            <input ref={inputRef} type="file" accept={apiMode ? ".csv,.txt,.tsv,.pcap,.pcapng" : ".csv,.txt,.tsv"} hidden
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
          </div>

          <div className="flex gap wrap" style={{ marginTop: 16 }}>
            <button className="btn primary" onClick={() => { loadDemo(); }} disabled={loading}>
              {loading ? "Analyzing…" : "▶ Run demo capture"}
            </button>
            <button className="btn" onClick={downloadDemo}>⤓ Download demo CSV</button>
          </div>
          <p className="faint" style={{ fontSize: 11.5, marginTop: 8 }}>
            The demo capture is a <b>synthetic kill-chain trace</b> in CIC-IDS flow schema. The world model itself is
            trained on the <b>real CSE-CIC-IDS2018 Infiltration day</b>; upload a real flow CSV above to run inference on it.
          </p>

          {warn && <div className="badge b-elev" style={{ marginTop: 14 }}><span className="dot" />{warn}</div>}
          {error && <div className="badge b-crit" style={{ marginTop: 14 }}><span className="dot" />{error}</div>}
        </Panel>

        <Panel title="Model Configuration">
          {apiMode ? (
            <>
              <Kv label="Forecast horizon K" value={`${result?.meta.K ?? 5} steps${result ? ` · ${result.meta.horizonSeconds}s` : ""}`} />
              <Kv label="ATT&CK stages" value={`${result?.model.cluster.k ?? 6} (benign + 5 kill-chain)`} />
              <Kv label="Window size" value={`${result ? Math.round(result.meta.horizonSeconds / result.meta.K) : 10}s`} />
              <Kv label="Sequence length (history)" value="8 windows" />
              <p className="faint" style={{ fontSize: 11.5, marginTop: 12 }}>
                Served by the trained CIC-IDS2018 world model — a fixed, reproducible configuration (seed 42),
                not a client-side refit. These reflect the actual model behind every number on this page.
              </p>
            </>
          ) : (
            <>
              <Param label="Forecast horizon K" value={params.K} min={2} max={10} onChange={(v) => setParams({ K: v })} suffix=" steps" />
              <Param label="Latent states (k)" value={params.k} min={3} max={12} onChange={(v) => setParams({ k: v })} />
              <Param label="Window size" value={params.windowMs / 1000} min={1} max={30} onChange={(v) => setParams({ windowMs: v * 1000 })} suffix="s" />
              <p className="faint" style={{ fontSize: 11.5, marginTop: 12 }}>
                In-browser engine (offline fallback). Re-load a capture after changing parameters to refit.
              </p>
            </>
          )}
        </Panel>
      </div>

      <div className="section-title">Pipeline</div>
      <div className="card">
        <div className="flex wrap" style={{ gap: 0, alignItems: "center" }}>
          {PIPE.map((p, i) => (
            <div key={p} className="flex center" style={{ gap: 0 }}>
              <div style={{ padding: "8px 14px", borderRadius: 9, border: "1px solid var(--border-2)", background: result ? "rgba(56,189,248,.08)" : "var(--panel-2)", fontSize: 12.5, fontWeight: 600, color: result ? "var(--brand)" : "var(--muted)" }}>
                {i + 1}. {p}
              </div>
              {i < PIPE.length - 1 && <span style={{ color: "var(--faint)", padding: "0 8px" }}>→</span>}
            </div>
          ))}
        </div>
      </div>

      {result && schema && (
        <>
          <div className="section-title">Detected Schema</div>
          <div className="card">
            <div className="flex between center wrap gap" style={{ marginBottom: 12 }}>
              <span className="badge b-info"><span className="dot" />{schema.dataset}</span>
              <span className="muted" style={{ fontSize: 12.5 }}>{schema.matched} known columns mapped · {result.meta.flows.toLocaleString()} flows · {result.meta.windows} windows</span>
            </div>
            <div className="flex wrap gap">
              {Object.entries(schema.mapping).filter(([, idx]) => idx >= 0).map(([field, idx]) => (
                <span key={field} className="pill">{field} ← {schema.columns[idx]}</span>
              ))}
            </div>
          </div>
        </>
      )}
      {result && (
        <div className="flex gap" style={{ marginTop: 16 }}>
          <button className="btn primary" onClick={() => router.push("/forecast")}>View forecast →</button>
          <span className="muted" style={{ alignSelf: "center", fontSize: 12.5 }}>Loaded: {source}</span>
        </div>
      )}
    </>
  );
}

function Param({ label, value, min, max, onChange, suffix = "" }: { label: string; value: number; min: number; max: number; onChange: (v: number) => void; suffix?: string }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div className="flex between" style={{ fontSize: 13, marginBottom: 6 }}>
        <span className="muted">{label}</span><span className="mono" style={{ color: "var(--brand)" }}>{value}{suffix}</span>
      </div>
      <input type="range" min={min} max={max} value={value} onChange={(e) => onChange(Number(e.target.value))}
        style={{ width: "100%", accentColor: "#38bdf8" }} />
    </div>
  );
}

function Kv({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex between" style={{ padding: "9px 0", borderBottom: "1px solid var(--line)", fontSize: 13 }}>
      <span className="muted">{label}</span>
      <span className="mono" style={{ color: "var(--brand)", fontWeight: 600 }}>{value}</span>
    </div>
  );
}
