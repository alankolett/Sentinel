"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useStore } from "@/lib/store";
import { useEffect, useState, useRef, useCallback, type ReactNode } from "react";

// Categorized Navigation Sections with crisp SVG Icons
const NAV_SECTIONS = [
  {
    title: "NAVIGATION",
    items: [
      {
        href: "/",
        label: "Overview",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="7" height="7" rx="1" />
            <rect x="14" y="3" width="7" height="7" rx="1" />
            <rect x="14" y="14" width="7" height="7" rx="1" />
            <rect x="3" y="14" width="7" height="7" rx="1" />
          </svg>
        ),
      },
      {
        href: "/dashboard",
        label: "Threat Operations",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        ),
      },
      {
        href: "/url-scan",
        label: "URL Predictor",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20" />
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
        ),
      },
      {
        href: "/simulation",
        label: "Live Simulation",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="5 3 19 12 5 21 5 3" />
          </svg>
        ),
      },
    ],
  },
  {
    title: "ANALYTICS & ML",
    items: [
      {
        href: "/analyze",
        label: "Upload & Analyze",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="17 8 12 3 7 8" />
            <line x1="12" y1="3" x2="12" y2="15" />
          </svg>
        ),
      },
      {
        href: "/alerts",
        label: "Threat Investigation",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        ),
      },
      {
        href: "/forecast",
        label: "Attack Forecast",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
          </svg>
        ),
      },
      {
        href: "/explain",
        label: "Explainability",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
          </svg>
        ),
      },
      {
        href: "/graph",
        label: "Network Graph",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="6" cy="6" r="3" />
            <circle cx="18" cy="6" r="3" />
            <circle cx="12" cy="18" r="3" />
            <line x1="8.5" y1="7.5" x2="15.5" y2="7.5" />
            <line x1="7.5" y1="8.5" x2="10.5" y2="15.5" />
            <line x1="16.5" y1="8.5" x2="13.5" y2="15.5" />
          </svg>
        ),
      },
    ],
  },
  {
    title: "DATA & EVAL",
    items: [
      {
        href: "/benchmark",
        label: "Benchmark",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="20" x2="18" y2="10" />
            <line x1="12" y1="20" x2="12" y2="4" />
            <line x1="6" y1="20" x2="6" y2="14" />
          </svg>
        ),
      },
      {
        href: "/dataset",
        label: "Dataset Explorer",
        icon: (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <ellipse cx="12" cy="5" rx="9" ry="3" />
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
          </svg>
        ),
      },
    ],
  },
];

export function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark">("light");
  useEffect(() => {
    const t = (document.documentElement.getAttribute("data-theme") as "light" | "dark") || "light";
    setTheme(t);
  }, []);

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("sentinel-theme", next);
    } catch {
      /* noop */
    }
  };

  return (
    <button
      className="theme-toggle"
      onClick={toggle}
      aria-label="Toggle visual theme"
      type="button"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
        padding: "8px 12px",
        borderRadius: "var(--radius, 6px)",
        border: "1px solid var(--border-default)",
        background: "var(--bg-surface-muted)",
        color: "var(--text-primary)",
        cursor: "pointer",
        fontWeight: 600,
        fontSize: 12,
        fontFamily: "var(--sans)",
        transition: "all 0.2s ease",
      }}
    >
      {theme === "dark" ? (
        <>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="5" />
            <line x1="12" y1="1" x2="12" y2="3" />
            <line x1="12" y1="21" x2="12" y2="23" />
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
            <line x1="1" y1="12" x2="3" y2="12" />
            <line x1="21" y1="12" x2="23" y2="12" />
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
          </svg>
          Light Mode
        </>
      ) : (
        <>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
          Dark Mode
        </>
      )}
    </button>
  );
}

export function Sidebar() {
  const path = usePathname();

  return (
    <aside className="sidebar" style={{ width: 240 }}>
      {/* Brand Header */}
      <Link href="/" className="brand" style={{ display: "flex", alignItems: "center", gap: 12, paddingBottom: 16, marginBottom: 16, borderBottom: "1px solid var(--border-subtle)" }}>
        <img
          src="/sentinel-logo.jpg"
          alt="Sentinel Logo"
          style={{
            width: 38,
            height: 38,
            borderRadius: 8,
            objectFit: "cover",
            border: "1px solid var(--border-default)",
            boxShadow: "0 2px 10px rgba(0, 0, 0, 0.3)",
            flexShrink: 0,
          }}
        />
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <b style={{ fontSize: 16, fontWeight: 800, letterSpacing: "-0.02em", color: "var(--text-primary)", lineHeight: 1.1 }}>
              SENTINEL
            </b>
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
          <div
            style={{
              fontSize: 9.5,
              fontWeight: 600,
              fontFamily: "var(--sans)",
              color: "var(--text-tertiary)",
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              marginTop: 2,
            }}
          >
            ATTACK FORECASTING
          </div>
        </div>
      </Link>

      {/* Navigation Groups */}
      <nav aria-label="Main Navigation" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
        {NAV_SECTIONS.map((sec) => (
          <div key={sec.title}>
            <div
              style={{
                fontFamily: "var(--mono)",
                fontSize: 9.5,
                fontWeight: 700,
                letterSpacing: "0.14em",
                color: "var(--text-tertiary)",
                textTransform: "uppercase",
                padding: "0 10px",
                marginBottom: 6,
              }}
            >
              {sec.title}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {sec.items.map((n) => {
                const isActive = path === n.href;
                return (
                  <Link
                    key={n.href}
                    href={n.href}
                    className={`nav-item ${isActive ? "active" : ""}`}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "8px 10px",
                      borderRadius: "var(--radius, 6px)",
                      color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
                      background: isActive ? "var(--brand-primary-muted)" : "transparent",
                      fontWeight: isActive ? 700 : 500,
                      fontSize: 13,
                      transition: "all 0.15s ease",
                      borderLeft: isActive ? "3px solid var(--brand-accent)" : "3px solid transparent",
                    }}
                  >
                    <span style={{ color: isActive ? "var(--brand-accent)" : "var(--text-tertiary)", display: "flex", alignItems: "center" }}>
                      {n.icon}
                    </span>
                    <span>{n.label}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="spacer" style={{ flex: 1, minHeight: 20 }} />

      {/* Live Model Status Widget */}
      <div
        style={{
          background: "var(--bg-surface-muted)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius, 6px)",
          padding: "10px 12px",
          marginBottom: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
          <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text-tertiary)", textTransform: "uppercase" }}>
            WORLD MODEL
          </span>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--security-safe)", boxShadow: "0 0 6px var(--security-safe)" }} />
        </div>
        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-primary)", marginBottom: 2 }}>
          P(Sₜ₊₁|Sₜ) Active Mesh
        </div>
        <div style={{ fontSize: 9.5, color: "var(--text-tertiary)", fontFamily: "var(--mono)" }}>
          79 Telemetry Features · Online
        </div>
      </div>

      <ThemeToggle />

      <div className="foot" style={{ fontSize: 10, color: "var(--text-tertiary)", paddingTop: 10, borderTop: "1px solid var(--border-subtle)" }}>
        <div>SIH26153 · NTRO Division</div>
        <div style={{ opacity: 0.7, fontSize: 9, marginTop: 2, fontFamily: "var(--mono)" }}>CIC-IDS2018 MODEL ENGINE</div>
      </div>
    </aside>
  );
}

export function ScrollX({ children, ariaLabel = "Scrollable content" }: { children: ReactNode; ariaLabel?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const update = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    setEdges({ left: el.scrollLeft > 4, right: el.scrollLeft < max - 4 });
  }, []);

  useEffect(() => {
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [update]);

  useEffect(() => {
    const t = setTimeout(update, 60);
    return () => clearTimeout(t);
  });

  const nudge = () => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    const next = el.scrollLeft + Math.round(el.clientWidth * 0.7);
    el.scrollLeft = next >= max - 4 ? max : next;
  };

  return (
    <div className={`scrollx-wrap ${edges.left ? "more-left" : ""} ${edges.right ? "more-right" : ""}`}>
      <div className="scrollx" ref={ref} onScroll={update}>
        {children}
      </div>
      {edges.right && (
        <button type="button" className="scrollx-more" onClick={nudge} aria-label={`${ariaLabel} — scroll right`}>
          ›
        </button>
      )}
    </div>
  );
}

export function MobileNav() {
  const path = usePathname();
  const navRef = useRef<HTMLElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const update = useCallback(() => {
    const el = navRef.current;
    if (!el) return;
    const max = el.scrollWidth - el.clientWidth;
    setEdges({ left: el.scrollLeft > 4, right: el.scrollLeft < max - 4 });
  }, []);

  useEffect(() => {
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [update]);

  const nudge = () => {
    const el = navRef.current;
    if (el) el.scrollBy({ left: Math.round(el.clientWidth * 0.7), behavior: "smooth" });
  };

  const allItems = NAV_SECTIONS.flatMap((s) => s.items);

  return (
    <div className="mobile-topbar">
      <div className="mobile-topbar-row">
        <Link href="/" className="brand" style={{ padding: 0, margin: 0, border: "none", display: "flex", alignItems: "center", gap: 8 }}>
          <img src="/sentinel-logo.jpg" alt="Sentinel Logo" style={{ width: 28, height: 28, borderRadius: 6, objectFit: "cover" }} />
          <b style={{ fontSize: 15 }}>SENTINEL</b>
        </Link>
        <ThemeToggle />
      </div>
      <div className={`mobile-nav-wrap ${edges.left ? "more-left" : ""} ${edges.right ? "more-right" : ""}`}>
        <nav className="mobile-nav" aria-label="Primary Mobile Navigation" ref={navRef} onScroll={update}>
          {allItems.map((n) => (
            <Link key={n.href} href={n.href} className={`nav-item ${path === n.href ? "active" : ""}`}>
              {n.label}
            </Link>
          ))}
        </nav>
        {edges.right && (
          <button type="button" className="mobile-nav-more" onClick={nudge} aria-label="More navigation links">
            ›
          </button>
        )}
      </div>
    </div>
  );
}

export function Topbar({ title, sub }: { title: string; sub: string }) {
  const { source, result } = useStore();
  const [env, setEnv] = useState("PRODUCTION-NET-01");
  const [lastUpdated, setLastUpdated] = useState("JUST NOW");

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      setLastUpdated(now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const exportIncidentReport = () => {
    const brief = {
      project: "Sentinel AI Network Attack Forecasting World Model",
      problemStatement: "SIH26153 - National Technical Research Organisation (NTRO)",
      domain: "Space Technology / Cyber Defense",
      timestamp: new Date().toISOString(),
      environment: env,
      metrics: {
        modelStatus: "ONLINE",
        latentFeatures: 79,
        forecastLeadTime: "+20 Seconds",
        recallAt5PercentFPR: "60.6% vs 13.5% Baseline (4.5x Gain)",
        activeSource: source || "CSE-CIC-IDS2018 Infiltration Benchmark",
        flowsProcessed: result ? result.meta.flows : 2550,
        predictedStage: result ? result.predictedStage : "Infiltration / Lateral Movement",
      },
      recommendedSOCAction: "EXECUTE-PLAYBOOK-ISOLATE-HOST-66",
    };

    const blob = new Blob([JSON.stringify(brief, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Sentinel_SOC_Incident_Brief_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="topbar">
      <div className="topbar-lead">
        <div className="flex center gap" style={{ marginBottom: 6 }}>
          <span className="eyebrow">
            SENTINEL INTELLIGENCE<i />
          </span>
          <select
            value={env}
            onChange={(e) => setEnv(e.target.value)}
            className="mono"
            style={{
              padding: "2px 6px",
              fontSize: 10,
              fontWeight: 600,
              background: "var(--bg-surface-muted)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 4,
            }}
            aria-label="Select Target Environment"
          >
            <option value="PRODUCTION-NET-01">ENV: US-EAST-PROD-01</option>
            <option value="DMZ-GATEWAY-02">ENV: DMZ-GATEWAY-02</option>
            <option value="INTERNAL-CORP-03">ENV: INTERNAL-CORP-03</option>
          </select>
        </div>
        <h1 className="display">{title}</h1>
        <p>{sub}</p>
      </div>

      <div className="flex center gap wrap" style={{ alignItems: "flex-end", gap: 12 }}>
        <button
          onClick={exportIncidentReport}
          className="btn"
          style={{
            fontSize: 11,
            padding: "5px 12px",
            background: "var(--bg-surface-muted)",
            border: "1px solid var(--border-default)",
            color: "var(--text-primary)",
            fontWeight: 600,
          }}
          title="Download official SOC Incident Brief (JSON)"
        >
          📄 Export Brief
        </button>

        <div className="flex center gap" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
          <span className="badge b-low" style={{ padding: "3px 6px", fontSize: 9.5 }}>
            <span className="dot" /> MODEL ONLINE
          </span>
          <span className="mono" style={{ fontSize: 10.5 }}>
            UPDATED: {lastUpdated}
          </span>
        </div>

        {result && source && (
          <div className="badge b-info" style={{ borderRadius: 4 }}>
            <span className="dot" />
            <span className="mono">{source.length > 36 ? source.slice(0, 36) + "…" : source}</span>
            <span>· {result.meta.flows.toLocaleString()} flows</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function NeedData({ children }: { children?: ReactNode }) {
  const { loadDemo, loading } = useStore();
  return (
    <div className="card" style={{ padding: 0, margin: "24px 40px" }}>
      <div className="empty">
        <div style={{ fontSize: 36, marginBottom: 12, color: "var(--brand-accent)" }}>◎</div>
        <h2 style={{ fontSize: 18, marginBottom: 6 }}>No Active Network Capture Loaded</h2>
        <p className="muted" style={{ maxWidth: 460, margin: "0 auto 20px", fontSize: 13 }}>
          {children ?? "Initialize the CIC-IDS2018 trained world model with benchmark capture telemetry, or upload a custom PCAP/Flow CSV."}
        </p>
        <button className="btn btn-primary" onClick={loadDemo} disabled={loading}>
          {loading ? "Initializing World Model…" : "▶ Run Telemetry Capture Demo"}
        </button>
      </div>
    </div>
  );
}
