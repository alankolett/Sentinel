// Core domain types for AegisChronos. Kept dependency-free and erasable-syntax
// only so the modules can be unit-tested directly with `node --test`.

/** A normalised bidirectional flow record (internal schema). */
export interface Flow {
  ts: number; // event time, ms
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string; // TCP | UDP | ICMP | ...
  syn: number;
  ack: number;
  fin: number;
  rst: number;
  psh: number;
  urg: number;
  bytes: number;
  packets: number;
  durationMs: number;
  iatMean: number;
  iatVar: number;
  iatMax: number;
  ttl?: number;
  ttlVar?: number;
  windowSize?: number; // TCP window size
  retrans?: number;
  fragmented?: number; // IP fragmentation flag (0/1)
  bwdBytes?: number; // reverse-direction bytes (for bidirectional ratio)
  label?: string; // ground-truth label if present (e.g. "BENIGN", "PortScan")
}

/** The MITRE ATT&CK stages we reason about. */
export const STAGES = [
  "Benign",
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
] as const;
export type Stage = (typeof STAGES)[number];

/** Ordered feature names for the per-window network-state vector. */
export const FEATURES = [
  "flowCount",
  "uniqueDstPorts",
  "uniqueDstIps",
  "synRatio",
  "synAckRatio",
  "rstRatio",
  "finRatio",
  "avgBytes",
  "avgPackets",
  "avgDuration",
  "iatMean",
  "iatVar",
  "portScanScore",
  "failedConnRatio",
  "lateralScore",
  "bytesOutRatio",
  "ttlVar",
  "retransRatio",
] as const;
export type FeatureName = (typeof FEATURES)[number];

/** A time-windowed observation of network state S_t. */
export interface WindowState {
  index: number;
  tStart: number;
  tEnd: number;
  vec: number[]; // aligned to FEATURES
  flowCount: number;
  malicious: boolean; // derived from labels (for eval only, never used at inference)
  topHosts: HostAgg[];
}

export interface HostAgg {
  ip: string;
  flows: number;
  dstPorts: number;
  peers: number;
  bytes: number;
  suspicion: number; // 0..1
}

export interface ClusterModel {
  k: number;
  centroids: number[][]; // in z-space
  mean: number[];
  std: number[];
  infiltration: number[]; // per-cluster infiltration score 0..1
  stage: Stage[]; // evidence-mapped stage per cluster
  sizes: number[];
}

/** Learned state-transition dynamics P(S_{t+1} | S_t). */
export interface TransitionModel {
  T: number[][]; // row-stochastic k x k
}

export interface ForecastStep {
  step: number; // t+step
  dist: number[]; // distribution over clusters
  infiltration: number; // expected infiltration probability
  topStage: Stage;
  confidence: number; // 1 - normalised entropy
}

export interface Attribution {
  feature: FeatureName;
  contribution: number; // signed, fraction of the score
  value: number;
  z: number;
}

export interface Metrics {
  precision: number;
  recall: number;
  f1: number;
  rocAuc: number;
  prAuc: number;
  fpr: number;
  accuracy: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}
