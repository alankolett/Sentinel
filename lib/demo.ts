// A synthetic-but-realistic labelled capture used for the zero-upload demo and
// for tests. Benign background traffic runs continuously across the whole
// timeline; an intrusion kill chain is overlaid as intermittent bursts, in
// order, with quiet gaps between them (a real attacker paces activity):
//   reconnaissance scan -> initial access (brute) -> lateral movement ->
//   command & control beacon -> exfiltration.
// Because benign and malicious activity interleave over time, a chronological
// train/test split contains both classes — enabling an honest benchmark — and
// the quiet gaps let a forecasting model raise the alarm before the next stage
// actually fires (measurable lead time). Deterministic under a fixed seed.

import type { Flow } from "./types.ts";
import { rng } from "./worldModel.ts";

const ATTACKER = "10.0.0.66";
const GATEWAY = "10.0.0.1";
const HOSTS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.21", "10.0.0.22"];
const EXTERNAL = ["203.0.113.5", "198.51.100.9", "8.8.8.8", "104.18.2.10"];

const SPAN = 6 * 60 * 1000; // 6 minutes

export function demoFlows(seed = 7): Flow[] {
  const r = rng(seed);
  const pick = <T>(a: T[]): T => a[Math.floor(r() * a.length)];
  const jit = (base: number, spread: number): number => base + (r() - 0.5) * spread;
  const t0 = Date.now() - SPAN;
  const flows: Flow[] = [];

  const mk = (ts: number, o: Partial<Flow> & { srcIp: string; dstIp: string; dstPort: number; label: string }): Flow => ({
    ts, srcPort: 1024 + Math.floor(r() * 64000), protocol: "TCP",
    syn: 1, ack: 1, fin: 0, rst: 0, psh: 0, urg: 0,
    bytes: Math.round(jit(800, 600)), packets: Math.max(1, Math.round(jit(8, 6))),
    durationMs: Math.round(jit(120, 100)), iatMean: jit(30, 20), iatVar: jit(10, 8), iatMax: jit(90, 40),
    ttl: 64, ttlVar: 1, windowSize: 65535, retrans: 0, fragmented: 0, bwdBytes: Math.round(jit(600, 400)),
    ...o,
  });

  // Continuous benign background across the full span (browsing/DNS/file share).
  for (let i = 0; i < 620; i++) {
    const ts = t0 + r() * SPAN;
    const internal = r() < 0.5;
    const src = pick(HOSTS);
    const dst = internal ? pick(HOSTS.filter((h) => h !== src)) : GATEWAY;
    flows.push(mk(ts, { srcIp: src, dstIp: dst, dstPort: pick([80, 443, 53]), bytes: Math.round(jit(2600, 4000)), bwdBytes: Math.round(jit(4200, 6000)), packets: Math.max(1, Math.round(jit(14, 10))), label: "BENIGN" }));
  }

  // Helper to place a burst of `count` flows inside a time sub-interval.
  const burst = (frac0: number, frac1: number, count: number, gen: (ts: number, i: number) => Flow) => {
    const a = t0 + frac0 * SPAN, b = t0 + frac1 * SPAN;
    for (let i = 0; i < count; i++) flows.push(gen(a + r() * (b - a), i));
  };

  // Stage 1 — reconnaissance: sequential port scan on one host (t ~ 25%..33%)
  burst(0.25, 0.33, 140, (ts, i) =>
    mk(ts, { srcIp: ATTACKER, dstIp: HOSTS[0], dstPort: 20 + (i % 130), syn: 1, ack: 0, rst: r() < 0.6 ? 1 : 0, bytes: 60, bwdBytes: 40, packets: 1, durationMs: 5, iatMean: jit(8, 4), label: "Reconnaissance" }));

  // Stage 2 — initial access: brute force to SSH/RDP (t ~ 42%..50%)
  burst(0.42, 0.5, 130, (ts, i) => {
    const success = i > 118;
    return mk(ts, { srcIp: ATTACKER, dstIp: HOSTS[1], dstPort: pick([22, 3389]), syn: 1, ack: success ? 1 : 0, rst: success ? 0 : 1, bytes: success ? 1400 : 120, bwdBytes: 80, packets: success ? 12 : 2, label: "Initial Access" });
  });

  // Stage 3 — lateral movement: pivot to internal peers over SMB/WinRM (t ~ 60%..68%)
  burst(0.6, 0.68, 120, (ts) =>
    mk(ts, { srcIp: HOSTS[1], dstIp: pick(HOSTS.filter((h) => h !== HOSTS[1])), dstPort: pick([445, 139, 3389, 5985]), syn: 1, ack: 1, bytes: Math.round(jit(3200, 2000)), bwdBytes: Math.round(jit(1800, 1500)), packets: Math.round(jit(20, 10)), label: "Lateral Movement" }));

  // Stage 4 — command & control: periodic low-volume beacon (t ~ 75%..82%)
  burst(0.75, 0.82, 90, (ts) =>
    mk(ts, { srcIp: HOSTS[1], dstIp: EXTERNAL[0], dstPort: 443, syn: 1, ack: 1, bytes: Math.round(jit(300, 60)), bwdBytes: Math.round(jit(200, 40)), packets: 4, durationMs: Math.round(jit(50, 10)), iatMean: 5000, iatVar: 40, label: "Command and Control" }));

  // Stage 5 — exfiltration: large sustained outbound transfer (t ~ 88%..99%,
  // runs to the end so the live "current state" reflects an active threat)
  burst(0.88, 0.995, 90, (ts) =>
    mk(ts, { srcIp: HOSTS[1], dstIp: EXTERNAL[1], dstPort: 443, syn: 1, ack: 1, psh: 1, bytes: Math.round(jit(120000, 40000)), bwdBytes: Math.round(jit(1500, 800)), packets: Math.round(jit(90, 30)), durationMs: Math.round(jit(400, 150)), label: "Exfiltration" }));

  flows.sort((a, b) => a.ts - b.ts);
  return flows;
}

/** Serialise the demo capture as a CIC-style CSV (for the download/upload demo). */
export function demoCsv(seed = 7): string {
  const flows = demoFlows(seed);
  const header = ["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "SYN Count", "ACK Count", "FIN Count", "RST Count", "PSH Count", "URG Count", "Total Bytes", "Total Bwd Bytes", "Total Packets", "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "TTL", "Init Win Bytes Forward", "Label"];
  const rows = flows.map((f) => [f.ts, f.srcIp, f.dstIp, f.srcPort, f.dstPort, f.protocol, f.syn, f.ack, f.fin, f.rst, f.psh, f.urg, f.bytes, f.bwdBytes ?? 0, f.packets, f.durationMs, f.iatMean.toFixed(2), f.iatVar.toFixed(2), f.iatMax.toFixed(2), f.ttl ?? 64, f.windowSize ?? 65535, f.label].join(","));
  return [header.join(","), ...rows].join("\n");
}
