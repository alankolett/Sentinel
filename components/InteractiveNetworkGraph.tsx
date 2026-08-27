"use client";

import { useState, useMemo } from "react";
import type { GraphNode, GraphEdge } from "@/lib/analyze";

interface InteractiveNetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectHost?: (ip: string) => void;
}

const W = 800, H = 480;

export function InteractiveNetworkGraph({ nodes, edges, onSelectHost }: InteractiveNetworkGraphProps) {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [hoveredIp, setHoveredIp] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Calculate layout coordinates for security hierarchy
  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number; role: string }>();
    if (!nodes || nodes.length === 0) return pos;

    const cx = W / 2, cy = H / 2;
    nodes.forEach((n, i) => {
      // Synthesize structured hierarchy based on IP / internal state
      let role = "workstation";
      if (!n.internal) role = "internet";
      else if (n.ip.endsWith(".1") || n.ip.endsWith(".254")) role = "gateway";
      else if (n.ip.endsWith(".200") || n.ip.endsWith(".100")) role = "server";
      else if (n.suspicion > 0.6) role = "compromised";

      const angle = (i / nodes.length) * Math.PI * 2;
      const distRatio = n.suspicion > 0.6 ? 0.35 : n.internal ? 0.65 : 0.88;
      const radius = distRatio * (Math.min(W, H) * 0.42);

      pos.set(n.ip, {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius * 0.85,
        role,
      });
    });

    return pos;
  }, [nodes]);

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleNodeClick = (ip: string) => {
    setSelectedIp(ip);
    if (onSelectHost) onSelectHost(ip);
  };

  const selectedNode = nodes.find((n) => n.ip === selectedIp);

  return (
    <div className="network-graph-wrap" style={{ position: "relative", width: "100%", overflow: "hidden" }}>
      {/* Zoom & Pan Controls */}
      <div style={{ position: "absolute", top: 12, right: 12, zIndex: 10, display: "flex", gap: 6 }}>
        <button
          className="btn"
          style={{ padding: "4px 8px", fontSize: 11 }}
          onClick={() => setZoom((z) => Math.min(z + 0.2, 2.0))}
          title="Zoom In"
        >
          +
        </button>
        <button
          className="btn"
          style={{ padding: "4px 8px", fontSize: 11 }}
          onClick={() => setZoom((z) => Math.max(z - 0.2, 0.6))}
          title="Zoom Out"
        >
          −
        </button>
        <button
          className="btn"
          style={{ padding: "4px 8px", fontSize: 11 }}
          onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
          title="Reset View"
        >
          Reset
        </button>
      </div>

      {/* SVG Interactive Canvas */}
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={H}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        style={{
          cursor: isDragging ? "grabbing" : "grab",
          background: "radial-gradient(circle at 50% 50%, var(--bg-surface-muted), var(--bg-surface))",
          borderRadius: "var(--radius)",
          userSelect: "none",
        }}
      >
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {/* Edge Connection Lines */}
          {edges.map((e, i) => {
            const a = layout.get(e.src);
            const b = layout.get(e.dst);
            if (!a || !b) return null;
            const isHighRisk = e.suspicious;
            const isHighlighted = hoveredIp === e.src || hoveredIp === e.dst;

            return (
              <g key={i}>
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={isHighRisk ? "var(--security-critical)" : isHighlighted ? "var(--brand-accent)" : "var(--border-default)"}
                  strokeWidth={isHighRisk ? 2 : isHighlighted ? 1.5 : 1}
                  strokeDasharray={isHighRisk ? "5 3" : undefined}
                  opacity={isHighlighted ? 1 : isHighRisk ? 0.85 : 0.4}
                />
                {/* Traffic direction indicator dot */}
                {isHighRisk && (
                  <circle r="3" fill="var(--security-critical)">
                    <animateMotion
                      path={`M ${a.x} ${a.y} L ${b.x} ${b.y}`}
                      dur="2.5s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            );
          })}

          {/* Network Nodes */}
          {nodes.map((n) => {
            const p = layout.get(n.ip);
            if (!p) return null;
            const isHovered = hoveredIp === n.ip;
            const isSelected = selectedIp === n.ip;
            const isCrit = n.suspicion > 0.6;
            const isWarn = n.suspicion > 0.35;
            const nodeColor = isCrit
              ? "var(--security-critical)"
              : isWarn
              ? "var(--security-warning)"
              : "var(--security-safe)";

            const radius = 8 + Math.min(14, Math.sqrt(n.flows) * 1.2);

            return (
              <g
                key={n.ip}
                onClick={() => handleNodeClick(n.ip)}
                onMouseEnter={() => setHoveredIp(n.ip)}
                onMouseLeave={() => setHoveredIp(null)}
                style={{ cursor: "pointer" }}
              >
                {/* Pulse Ring for Critical Suspicion */}
                {isCrit && (
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={radius + 8}
                    fill="none"
                    stroke={nodeColor}
                    strokeWidth="1.5"
                    opacity="0.5"
                    style={{ animation: "pulseGlow 2s infinite" }}
                  />
                )}

                {/* Selected Halo */}
                {isSelected && (
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={radius + 6}
                    fill="none"
                    stroke="var(--brand-accent)"
                    strokeWidth="2"
                  />
                )}

                <circle
                  cx={p.x}
                  cy={p.y}
                  r={radius}
                  fill={nodeColor}
                  stroke="var(--bg-surface)"
                  strokeWidth="2"
                />

                <text
                  x={p.x}
                  y={p.y + radius + 12}
                  textAnchor="middle"
                  fontSize="9.5"
                  fill={isHovered ? "var(--text-primary)" : "var(--text-tertiary)"}
                  className="mono"
                  fontWeight={isHovered || isSelected ? "700" : "500"}
                >
                  {n.ip}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Hover Node Tooltip */}
      {hoveredIp && !selectedIp && (
        <div
          style={{
            position: "absolute",
            bottom: 16,
            left: 16,
            padding: "8px 12px",
            background: "var(--bg-surface-elevated)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius)",
            boxShadow: "var(--shadow-md)",
            fontSize: 11,
            pointerEvents: "none",
          }}
        >
          <div className="mono" style={{ fontWeight: 700, color: "var(--text-primary)" }}>
            Host: {hoveredIp}
          </div>
          <div className="muted" style={{ fontSize: 10 }}>
            Click node to view host investigation details
          </div>
        </div>
      )}

      {/* Selected Host Details Modal/Drawer */}
      {selectedNode && (
        <div
          style={{
            position: "absolute",
            top: 12,
            left: 12,
            width: 260,
            padding: "14px 16px",
            background: "var(--bg-surface-elevated)",
            border: "1px solid var(--border-strong)",
            borderRadius: "var(--radius)",
            boxShadow: "var(--shadow-lg)",
            zIndex: 20,
          }}
        >
          <div className="flex between center" style={{ marginBottom: 10, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
            <span className="tag">HOST DETAILS</span>
            <button
              onClick={() => setSelectedIp(null)}
              style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-tertiary)", fontSize: 14 }}
            >
              ✕
            </button>
          </div>
          <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)", marginBottom: 8 }}>
            {selectedNode.ip}
          </div>
          <div style={{ fontSize: 12, marginBottom: 4 }} className="flex between">
            <span className="muted">Scope:</span>
            <span>{selectedNode.internal ? "Internal Network" : "External Internet"}</span>
          </div>
          <div style={{ fontSize: 12, marginBottom: 4 }} className="flex between">
            <span className="muted">Flow Count:</span>
            <span className="mono">{selectedNode.flows}</span>
          </div>
          <div style={{ fontSize: 12, marginBottom: 10 }} className="flex between">
            <span className="muted">Suspicion Score:</span>
            <span className={`badge ${selectedNode.suspicion > 0.6 ? "b-crit" : "b-elev"}`}>
              {(selectedNode.suspicion * 100).toFixed(0)}%
            </span>
          </div>
          <div className="flex gap" style={{ marginTop: 12 }}>
            <a href="/alerts" className="btn btn-primary" style={{ width: "100%", fontSize: 11, padding: "5px 8px" }}>
              Investigate Host
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
