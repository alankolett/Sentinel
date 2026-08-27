// Temporal windowing + per-window network-state feature extraction.
// Flows are grouped into chronological windows; each window becomes a state
// vector S_t aligned to FEATURES in ./types.

import type { Flow, WindowState, HostAgg } from "./types.ts";
import { FEATURES } from "./types.ts";
import { isAttackLabel } from "./parse.ts";

export interface WindowOpts {
  windowMs: number; // window size
  strideMs: number; // sliding interval
}

export const DEFAULT_WINDOW: WindowOpts = { windowMs: 5000, strideMs: 5000 };

const isPrivate = (ip: string): boolean =>
  /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip === "127.0.0.1";

/** Sequentiality of destination-port access — a slow/sequential scan signature. */
function portScanScore(ports: number[]): number {
  const uniq = Array.from(new Set(ports)).sort((a, b) => a - b);
  if (uniq.length < 4) return 0;
  let steps = 0;
  for (let i = 1; i < uniq.length; i++) if (uniq[i] - uniq[i - 1] <= 3) steps++;
  const sequentiality = steps / (uniq.length - 1);
  const breadth = Math.min(1, uniq.length / 50); // many distinct ports = fan-out scan
  return Math.max(sequentiality, breadth);
}

function aggHosts(flows: Flow[]): HostAgg[] {
  const map = new Map<string, { flows: number; ports: Set<number>; peers: Set<string>; bytes: number; syn: number; ack: number }>();
  for (const f of flows) {
    let h = map.get(f.srcIp);
    if (!h) { h = { flows: 0, ports: new Set(), peers: new Set(), bytes: 0, syn: 0, ack: 0 }; map.set(f.srcIp, h); }
    h.flows++;
    h.ports.add(f.dstPort);
    h.peers.add(f.dstIp);
    h.bytes += f.bytes;
    h.syn += f.syn;
    h.ack += f.ack;
  }
  const out: HostAgg[] = [];
  for (const [ip, h] of map) {
    const scan = Math.min(1, h.ports.size / 30);
    const fanout = Math.min(1, h.peers.size / 15);
    const failed = h.syn > 0 ? Math.max(0, (h.syn - h.ack) / h.syn) : 0;
    const suspicion = Math.min(1, 0.45 * scan + 0.35 * fanout + 0.2 * failed);
    out.push({ ip, flows: h.flows, dstPorts: h.ports.size, peers: h.peers.size, bytes: h.bytes, suspicion });
  }
  return out.sort((a, b) => b.suspicion - a.suspicion || b.flows - a.flows);
}

function buildVector(flows: Flow[]): number[] {
  const n = flows.length;
  let syn = 0, ack = 0, fin = 0, rst = 0, bytes = 0, bwd = 0, packets = 0, dur = 0, iatM = 0, iatV = 0, ttlV = 0, retr = 0;
  const dstPorts: number[] = [];
  const dstIps = new Set<string>();
  let lateralFlows = 0;
  for (const f of flows) {
    syn += f.syn; ack += f.ack; fin += f.fin; rst += f.rst;
    bytes += f.bytes; bwd += f.bwdBytes ?? 0; packets += f.packets; dur += f.durationMs;
    iatM += f.iatMean; iatV += f.iatVar; ttlV += f.ttlVar ?? 0; retr += f.retrans ?? 0;
    dstPorts.push(f.dstPort);
    dstIps.add(f.dstIp);
    if (isPrivate(f.srcIp) && isPrivate(f.dstIp)) lateralFlows++;
  }
  const synTot = syn || 1;
  const uniqPorts = new Set(dstPorts).size;
  const failedConn = Math.max(0, (syn - ack) / synTot); // SYN not answered by ACK
  const bytesOutRatio = bytes + bwd > 0 ? bytes / (bytes + bwd) : 0.5;
  const vec: Record<string, number> = {
    flowCount: n,
    uniqueDstPorts: uniqPorts,
    uniqueDstIps: dstIps.size,
    synRatio: syn / (packets || 1),
    synAckRatio: syn / (ack || 1),
    rstRatio: rst / (packets || 1),
    finRatio: fin / (packets || 1),
    avgBytes: bytes / n,
    avgPackets: packets / n,
    avgDuration: dur / n,
    iatMean: iatM / n,
    iatVar: iatV / n,
    portScanScore: portScanScore(dstPorts),
    failedConnRatio: failedConn,
    lateralScore: lateralFlows / n,
    bytesOutRatio,
    ttlVar: ttlV / n,
    retransRatio: retr / (packets || 1),
  };
  return FEATURES.map((k) => {
    const v = vec[k];
    return Number.isFinite(v) ? v : 0;
  });
}

/** Slice flows into sliding windows and compute the state vector for each. */
export function buildWindows(flows: Flow[], opts: WindowOpts = DEFAULT_WINDOW): WindowState[] {
  if (flows.length === 0) return [];
  const t0 = flows[0].ts;
  const tN = flows[flows.length - 1].ts;
  const span = Math.max(1, tN - t0);
  // If the capture is short or timestamps are degenerate, fall back to
  // fixed-size count windows so we always produce a usable temporal sequence.
  const useTime = span > opts.windowMs * 2;
  const windows: WindowState[] = [];
  let idx = 0;

  if (useTime) {
    for (let start = t0; start <= tN; start += opts.strideMs) {
      const end = start + opts.windowMs;
      const inWin = flows.filter((f) => f.ts >= start && f.ts < end);
      if (inWin.length === 0) continue;
      windows.push(makeWindow(idx++, start, end, inWin));
    }
  } else {
    const per = Math.max(5, Math.ceil(flows.length / Math.min(40, Math.max(6, Math.floor(flows.length / 20)))));
    for (let i = 0; i < flows.length; i += per) {
      const chunk = flows.slice(i, i + per);
      windows.push(makeWindow(idx++, chunk[0].ts, chunk[chunk.length - 1].ts, chunk));
    }
  }
  return windows;
}

function makeWindow(index: number, tStart: number, tEnd: number, inWin: Flow[]): WindowState {
  const mal = inWin.some((f) => isAttackLabel(f.label));
  return {
    index,
    tStart,
    tEnd,
    vec: buildVector(inWin),
    flowCount: inWin.length,
    malicious: mal,
    topHosts: aggHosts(inWin).slice(0, 6),
  };
}
