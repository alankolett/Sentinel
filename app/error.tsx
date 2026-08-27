"use client";

// Global error boundary — any unexpected render/runtime error is caught here
// so the app degrades gracefully instead of white-screening. Recovery re-mounts
// the subtree without a full reload.

import { useEffect } from "react";

export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => { console.error("Sentinel runtime error:", error); }, [error]);
  return (
    <div style={{ display: "grid", placeItems: "center", minHeight: "70vh", padding: 24, textAlign: "center" }}>
      <div className="card" style={{ maxWidth: 520 }}>
        <div className="scan-accent" />
        <div style={{ fontSize: 38, marginBottom: 10 }}>⚠</div>
        <h2 style={{ fontSize: 18, marginBottom: 8 }}>Something went wrong</h2>
        <p className="muted" style={{ fontSize: 13, marginBottom: 18 }}>
          The analysis view hit an unexpected error. Your data never left the browser. You can retry, or reload the demo capture.
        </p>
        {error?.message && <p className="mono faint" style={{ fontSize: 11.5, marginBottom: 18, wordBreak: "break-word" }}>{error.message}</p>}
        <div className="flex gap" style={{ justifyContent: "center" }}>
          <button className="btn primary" onClick={() => reset()}>↻ Retry</button>
          <a className="btn" href="/">Back to dashboard</a>
        </div>
      </div>
    </div>
  );
}
