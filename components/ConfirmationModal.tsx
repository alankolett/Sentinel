"use client";

import { useState } from "react";

interface ConfirmationModalProps {
  isOpen: boolean;
  title: string;
  description: string;
  targetHost?: string;
  actionLabel?: string;
  isDangerous?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

export function ConfirmationModal({
  isOpen,
  title,
  description,
  targetHost,
  actionLabel = "Confirm Action",
  isDangerous = true,
  onConfirm,
  onClose,
}: ConfirmationModalProps) {
  const [confirmInput, setConfirmInput] = useState("");

  if (!isOpen) return null;

  const requiresInput = isDangerous && targetHost;
  const isValid = !requiresInput || confirmInput.trim() === targetHost;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(15, 23, 42, 0.6)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 440,
          background: "var(--bg-surface-elevated)",
          border: isDangerous ? "1px solid var(--security-critical)" : "1px solid var(--border-default)",
          borderRadius: "var(--radius)",
          padding: 24,
          boxShadow: "var(--shadow-lg)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex between center" style={{ marginBottom: 12 }}>
          <div className="tag" style={{ color: isDangerous ? "var(--security-critical)" : "var(--text-tertiary)" }}>
            {isDangerous ? "⚠️ DANGEROUS DEFENDER ACTION" : "CONFIRM ACTION"}
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-tertiary)" }}>
            ✕
          </button>
        </div>

        <h3 style={{ fontSize: 18, marginBottom: 8, color: "var(--text-primary)" }}>{title}</h3>
        <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 16, lineHeight: 1.5 }}>
          {description}
        </p>

        {targetHost && (
          <div
            style={{
              padding: "10px 12px",
              background: "var(--bg-surface-muted)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius)",
              marginBottom: 16,
            }}
          >
            <span className="muted" style={{ fontSize: 11 }}>Target System: </span>
            <strong className="mono" style={{ fontSize: 13, color: "var(--text-primary)" }}>
              {targetHost}
            </strong>
          </div>
        )}

        {requiresInput && (
          <div style={{ marginBottom: 20 }}>
            <label className="muted" style={{ fontSize: 11, display: "block", marginBottom: 6 }}>
              Type <strong className="mono">{targetHost}</strong> to confirm isolation:
            </label>
            <input
              type="text"
              className="mono"
              style={{ width: "100%" }}
              placeholder={targetHost}
              value={confirmInput}
              onChange={(e) => setConfirmInput(e.target.value)}
            />
          </div>
        )}

        <div className="flex between gap" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className={`btn ${isDangerous ? "btn-danger" : "btn-primary"}`}
            disabled={!isValid}
            onClick={() => {
              onConfirm();
              onClose();
            }}
          >
            {actionLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
