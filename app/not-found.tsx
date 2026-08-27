import Link from "next/link";

export default function NotFound() {
  return (
    <div style={{ display: "grid", placeItems: "center", minHeight: "70vh", padding: 24, textAlign: "center" }}>
      <div className="card" style={{ maxWidth: 460 }}>
        <div className="scan-accent" />
        <div style={{ fontSize: 40, marginBottom: 10 }}>◎</div>
        <h2 style={{ fontSize: 20, marginBottom: 6 }}>404 — page not found</h2>
        <p className="muted" style={{ fontSize: 13, marginBottom: 18 }}>This route is not part of the Sentinel console.</p>
        <Link className="btn primary" href="/">Back to dashboard</Link>
      </div>
    </div>
  );
}
