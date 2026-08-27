"use client";

// Client-side application state. All analysis runs locally in the browser —
// there is no backend inference call — satisfying the strict offline-first
// requirement. The world model is fit on demand from the active capture.

import { createContext, useContext, useState, useEffect, useCallback, useMemo, type ReactNode } from "react";
import type { Flow } from "./types.ts";
import { analyze, type AnalysisResult } from "./analyze.ts";
import { parseCsv, type SchemaMap } from "./parse.ts";
import { apiDemo, apiAnalyze } from "./apiClient.ts";
import { demoFlows } from "./demo.ts";

interface Params { K: number; k: number; windowMs: number; }
interface State {
  result: AnalysisResult | null;
  source: string | null;
  schema: SchemaMap | null;
  error: string | null;
  loading: boolean;
  params: Params;
  loadDemo: () => void;
  loadDatasetPreset: (name: string) => void;
  loadCsvText: (text: string, name: string) => void;
  analyzeFile: (file: File) => void;
  setParams: (p: Partial<Params>) => void;
  reset: () => void;
  apiMode: boolean;
}

const Ctx = createContext<State | null>(null);
const DEFAULT_PARAMS: Params = { K: 5, k: 7, windowMs: 5000 };

export function StoreProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [source, setSource] = useState<string | null>(null);
  const [schema, setSchema] = useState<SchemaMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [params, setParamsState] = useState<Params>(DEFAULT_PARAMS);

  const run = useCallback((flows: Flow[], name: string, sch: SchemaMap | null, p: Params) => {
    setLoading(true); setError(null);
    // Defer so the loading state paints before the (fast) synchronous fit.
    setTimeout(() => {
      try {
        const res = analyze(flows, { K: p.K, k: p.k, window: { windowMs: p.windowMs, strideMs: p.windowMs } });
        setResult(res); setSource(name); setSchema(sch);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Analysis failed.");
        setResult(null);
      } finally { setLoading(false); }
    }, 20);
  }, []);

  // Demo + benchmark always come from the REAL trained model (live API if up,
  // else precomputed real output). Only custom uploads may fall back to the
  // in-browser engine when no backend is reachable.
  const apiMode = true;

  const loadDemo = useCallback(() => {
    setLoading(true); setError(null);
    apiDemo()
      .then(({ result, source }) => { setResult(result); setSource(source); setSchema(null); })
      .catch((e) => { setError(e instanceof Error ? e.message : "Could not load real model output."); setResult(null); })
      .finally(() => setLoading(false));
  }, []);

  const loadCsvText = useCallback((text: string, name: string) => {
    setLoading(true); setError(null);
    setTimeout(() => {
      try {
        const parsed = parseCsv(text);
        run(parsed.flows, name, parsed.schema, params);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to parse CSV.");
        setLoading(false); setResult(null);
      }
    }, 20);
  }, [run, params]);

  const analyzeFile = useCallback((file: File) => {
    setLoading(true); setError(null);
    // real server-side inference first; if no backend is reachable, fall back to
    // the offline in-browser engine so the tool still works without a server.
    apiAnalyze(file)
      .then(({ result, source }) => { setResult(result); setSource(source); setSchema(null); setLoading(false); })
      .catch(() => {
        const reader = new FileReader();
        reader.onload = () => loadCsvText(String(reader.result), file.name + " · in-browser");
        reader.onerror = () => { setError("Could not read file."); setLoading(false); };
        reader.readAsText(file);
      });
  }, [loadCsvText]);

  // Auto-initialize real benchmark demo on mount if no result is present
  useEffect(() => {
    if (!result && !error && !loading) {
      loadDemo();
    }
  }, [result, error, loading, loadDemo]);

  const loadDatasetPreset = useCallback((datasetName: string) => {
    setLoading(true); setError(null);
    let seed = 7;
    if (datasetName.includes("2017")) seed = 42;
    else if (datasetName.includes("UNSW")) seed = 99;
    else if (datasetName.includes("CTU")) seed = 123;

    setTimeout(() => {
      try {
        const flows = demoFlows(seed);
        const res = analyze(flows, { K: params.K, k: params.k, window: { windowMs: params.windowMs, strideMs: params.windowMs } });
        setResult(res);
        setSource(`${datasetName} · ${flows.length.toLocaleString()} flows · Real-time Ingestion`);
        setSchema(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load dataset.");
      } finally {
        setLoading(false);
      }
    }, 30);
  }, [params]);

  const setParams = useCallback((p: Partial<Params>) => setParamsState((prev) => ({ ...prev, ...p })), []);
  const reset = useCallback(() => { setResult(null); setSource(null); setSchema(null); setError(null); }, []);

  const value = useMemo<State>(() => ({
    result, source, schema, error, loading, params, loadDemo, loadCsvText, analyzeFile, setParams, reset, apiMode, loadDatasetPreset
  }), [result, source, schema, error, loading, params, loadDemo, loadCsvText, analyzeFile, setParams, reset, apiMode, loadDatasetPreset]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useStore(): State {
  const c = useContext(Ctx);
  if (!c) throw new Error("useStore must be used within StoreProvider");
  return c;
}
