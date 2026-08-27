"use client";

import { useStore } from "@/lib/store";
import { Topbar, NeedData, ScrollX } from "@/components/shell";
import { Panel } from "@/components/charts";
import { InteractiveNetworkGraph } from "@/components/InteractiveNetworkGraph";

export default function GraphPage() {
  const { result } = useStore();
  if (!result)
    return (
      <>
        <Topbar title="Network Topology & Path Graph" sub="Communication relationships & suspicious lateral paths" />
        <NeedData />
      </>
    );

  const r = result;

  const nodeColor = (s: number) => (s > 0.6 ? "var(--security-critical)" : s > 0.35 ? "var(--security-warning)" : "var(--brand-accent)");

  return (
    <>
      <Topbar title="Network Topology & Path Graph" sub="Hosts as nodes · communication flows as edges · suspicious paths highlighted" />

      <div className="main">
        <div className="grid cols-2" style={{ gridTemplateColumns: "1.7fr 1fr", marginBottom: 20 }}>
          <Panel
            accent
            title="Interactive Network Topology Graph"
            right={
              <span className="pill">
                {r.graph.nodes.length} Hosts · {r.graph.edges.length} Communication Edges
              </span>
            }
          >
            <InteractiveNetworkGraph nodes={r.graph.nodes} edges={r.graph.edges} />

            <div className="legend" style={{ marginTop: 12 }}>
              <span><i style={{ background: "var(--security-critical)" }} /> High Suspicion Host (&gt;60%)</span>
              <span><i style={{ background: "var(--security-warning)" }} /> Elevated Suspicion Host</span>
              <span><i style={{ background: "var(--security-safe)" }} /> Normal Host</span>
              <span><i style={{ background: "var(--security-critical)" }} /> Suspicious Edge (Port Scan / SMB Burst)</span>
            </div>
          </Panel>

          <Panel title="Host Security Inventory">
            <ScrollX ariaLabel="Suspicious hosts table">
              <table style={{ minWidth: 360 }}>
                <thead>
                  <tr>
                    <th>Host IP</th>
                    <th>Scope</th>
                    <th>Flows</th>
                    <th>Suspicion</th>
                  </tr>
                </thead>
                <tbody>
                  {r.graph.nodes.slice(0, 14).map((n) => (
                    <tr key={n.ip}>
                      <td className="mono" style={{ color: nodeColor(n.suspicion), fontWeight: 700 }}>
                        {n.ip}
                      </td>
                      <td>
                        <span className="tag">{n.internal ? "Internal" : "External"}</span>
                      </td>
                      <td className="mono">{n.flows}</td>
                      <td>
                        <span className={`badge ${n.suspicion > 0.6 ? "b-crit" : n.suspicion > 0.35 ? "b-elev" : "b-low"}`}>
                          {(n.suspicion * 100).toFixed(0)}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollX>
            <p className="faint" style={{ fontSize: 11, marginTop: 14, lineHeight: 1.5 }}>
              Suspicion combines destination-port scanning breadth, peer fanout, and unanswered-SYN ratios. Click any node in the graph to inspect host telemetry.
            </p>
          </Panel>
        </div>
      </div>
    </>
  );
}
