"use client";

import { STAGE_TECHNIQUE } from "@/lib/attack";
import type { Stage } from "@/lib/types";

const KILL_CHAIN: Stage[] = [
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Command and Control",
  "Exfiltration",
];

export function MitreMatrix({ currentStage, predictedStage }: { currentStage: Stage; predictedStage?: Stage }) {
  return (
    <div className="mitre-matrix">
      <style>{`
        .mitre-matrix { display: flex; flex-wrap: wrap; gap: 4px; }
        .mitre-stage {
          flex: 1 1 calc(33.333% - 4px);
          min-width: 120px;
          padding: 10px;
          background: var(--panel-2);
          border: 1px solid var(--line);
          border-radius: 4px;
          display: flex;
          flex-direction: column;
          position: relative;
          transition: all .2s var(--ease);
        }
        .mitre-stage .stage-name { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text); }
        .mitre-stage .technique { font-size: 9px; font-family: var(--mono); color: var(--faint); margin-top: 4px; }
        .mitre-stage.current { border-color: var(--warn); background: var(--warn-dim); }
        .mitre-stage.predicted { border-color: var(--crit); background: var(--crit-dim); box-shadow: 0 0 10px rgba(255,0,60,0.2); }
        .mitre-stage.current::after { content: "CURRENT"; position: absolute; top: 4px; right: 6px; font-size: 8px; font-weight: bold; color: var(--warn); }
        .mitre-stage.predicted::after { content: "PREDICTED"; position: absolute; top: 4px; right: 6px; font-size: 8px; font-weight: bold; color: var(--crit); }
      `}</style>
      
      {KILL_CHAIN.map((stage) => {
        const isCurrent = currentStage === stage;
        const isPredicted = predictedStage === stage && !isCurrent;
        let className = "mitre-stage";
        if (isCurrent) className += " current";
        if (isPredicted) className += " predicted";

        return (
          <div key={stage} className={className}>
            <div className="stage-name">{stage}</div>
            <div className="technique">{STAGE_TECHNIQUE[stage] || "—"}</div>
          </div>
        );
      })}
    </div>
  );
}
