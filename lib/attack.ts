// Evidence-based MITRE ATT&CK stage mapping. A latent cluster is characterised
// by its centroid's real (de-standardised) feature signature; stages are
// assigned from behavioural evidence rules, never asserted blindly.

import type { Stage } from "./types.ts";
import { FEATURES } from "./types.ts";
import type { Standardizer } from "./worldModel.ts";

export interface ClusterSignature {
  f: Record<string, number>; // de-normalised feature values
  z: Record<string, number>; // z-scores (how anomalous each feature is)
  risk: number; // 0..1 unsupervised behavioural risk
  evidence: string[]; // human-readable driving evidence
}

const sigmoid = (x: number): number => 1 / (1 + Math.exp(-x));

/** Turn a centroid (z-space) into an interpretable behavioural signature. */
export function clusterInfiltrationSignature(centroidZ: number[], std: Standardizer): ClusterSignature {
  const f: Record<string, number> = {};
  const z: Record<string, number> = {};
  FEATURES.forEach((name, j) => {
    f[name] = centroidZ[j] * std.std[j] + std.mean[j];
    z[name] = centroidZ[j];
  });
  const evidence: string[] = [];
  // Weighted behavioural risk from anomaly of security-relevant features.
  const w: Record<string, number> = {
    portScanScore: 1.6, failedConnRatio: 1.4, synAckRatio: 1.0, uniqueDstPorts: 1.2,
    lateralScore: 1.5, rstRatio: 0.8, synRatio: 0.9, iatVar: 0.7, retransRatio: 0.6,
    uniqueDstIps: 0.9, bytesOutRatio: 0.7, ttlVar: 0.5,
  };
  let acc = 0, wsum = 0;
  for (const k of Object.keys(w)) { acc += w[k] * Math.max(0, z[k]); wsum += w[k]; }
  const risk = sigmoid(acc / (wsum || 1) - 0.15);

  if (z.portScanScore > 0.8 || f.portScanScore > 0.5) evidence.push("Sequential/broad destination-port access (scan signature)");
  if (z.uniqueDstPorts > 1) evidence.push("Elevated distinct destination ports");
  if (z.failedConnRatio > 0.8 || f.failedConnRatio > 0.5) evidence.push("High rate of unanswered SYNs (failed connections)");
  if (z.synAckRatio > 1) evidence.push("Abnormal SYN/ACK ratio (half-open connections)");
  if (z.lateralScore > 0.8) evidence.push("Internal-to-internal fan-out (lateral communication)");
  if (z.rstRatio > 1) evidence.push("Elevated RST rate (probing / rejected connections)");
  if (z.bytesOutRatio > 1 && f.avgBytes > 0) evidence.push("Outbound-skewed byte volume");
  if (z.iatVar > 1) evidence.push("Irregular inter-arrival timing");
  return { f, z, risk, evidence };
}

/** Map a cluster signature to the most consistent ATT&CK stage. */
export function mapClusterStage(sig: ClusterSignature, infiltration: number): Stage {
  const { f, z } = sig;
  if (infiltration < 0.2 && z.portScanScore <= 0.5 && z.lateralScore <= 0.5) return "Benign";
  // Ordered by kill-chain specificity; first satisfied rule wins.
  if (f.portScanScore > 0.5 && f.uniqueDstPorts > 8) return "Reconnaissance";
  if (z.uniqueDstIps > 1 && z.portScanScore > 0.4) return "Discovery";
  if (z.failedConnRatio > 0.8 && z.synAckRatio > 0.6) return "Credential Access";
  if (z.synRatio > 1 && z.failedConnRatio > 0.5) return "Initial Access";
  if (z.lateralScore > 0.6) return "Lateral Movement";
  if (z.iatVar < 0 && f.flowCount > 0 && z.bytesOutRatio > 0.4 && z.uniqueDstIps < 0) return "Command and Control";
  if (z.bytesOutRatio > 1) return "Exfiltration";
  if (z.rstRatio > 1) return "Defense Evasion";
  if (infiltration > 0.5) return "Initial Access";
  return "Benign";
}

/** Short ATT&CK technique hint for a stage (indicative, evidence-gated). */
export const STAGE_TECHNIQUE: Record<Stage, string> = {
  Benign: "—",
  Reconnaissance: "T1595 Active Scanning",
  "Initial Access": "T1190 Exploit Public-Facing App",
  Execution: "T1059 Command & Scripting",
  Persistence: "T1053 Scheduled Task",
  "Privilege Escalation": "T1068 Exploitation for Priv-Esc",
  "Defense Evasion": "T1070 Indicator Removal",
  "Credential Access": "T1110 Brute Force",
  Discovery: "T1046 Network Service Discovery",
  "Lateral Movement": "T1021 Remote Services",
  "Command and Control": "T1071 Application Layer Protocol",
  Exfiltration: "T1041 Exfil Over C2 Channel",
};
