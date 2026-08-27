// CSV ingestion with automatic schema detection across common public datasets
// (CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023). Header names are matched
// case/whitespace-insensitively against a synonym table so heterogeneous exports
// map onto the single internal Flow schema.

import type { Flow } from "./types.ts";

const norm = (s: string): string => s.trim().toLowerCase().replace(/[\s_]+/g, "").replace(/[^a-z0-9]/g, "");

// Map internal field -> list of accepted source-header synonyms (normalised).
const SYNONYMS: Record<string, string[]> = {
  ts: ["timestamp", "time", "stime", "flowstarttime", "ts", "starttime"],
  srcIp: ["srcip", "sourceip", "sourceipaddress", "sa", "sourceaddress", "ipsrc", "id.origh"],
  dstIp: ["dstip", "destinationip", "da", "destinationipaddress", "ipdst", "id.resph"],
  srcPort: ["srcport", "sport", "sourceport", "l4srcport", "id.origp"],
  dstPort: ["dstport", "dport", "destinationport", "l4dstport", "id.respp"],
  protocol: ["protocol", "proto", "protocolname"],
  bytes: ["bytes", "totbytes", "totalbytes", "sbytes", "totlenfwdpackets", "totalfwdbytes", "origbytes", "inbytes"],
  bwdBytes: ["dbytes", "totlenbwdpackets", "totalbwdbytes", "respbytes", "outbytes"],
  packets: ["packets", "totpkts", "totalpackets", "spkts", "totalfwdpackets", "origpkts"],
  durationMs: ["duration", "flowduration", "dur"],
  syn: ["syncount", "syn", "synflagcount", "tcpflagssyn"],
  ack: ["ackcount", "ack", "ackflagcount"],
  fin: ["fincount", "fin", "finflagcount"],
  rst: ["rstcount", "rst", "rstflagcount"],
  psh: ["pshcount", "psh", "pshflagcount", "fwdpshflags"],
  urg: ["urgcount", "urg", "urgflagcount", "fwdurgflags"],
  flags: ["flags", "tcpflags", "state", "conn_state"],
  iatMean: ["flowiatmean", "iatmean", "meaniat"],
  iatVar: ["flowiatstd", "iatvar", "flowiatvar"],
  iatMax: ["flowiatmax", "iatmax"],
  ttl: ["ttl", "sttl", "meanttl"],
  ttlVar: ["ttlvar", "ttlstd"],
  windowSize: ["initwinbytesforward", "windowsize", "tcpwindow", "swin"],
  retrans: ["retrans", "retransmissions", "tcprtt"],
  fragmented: ["fragmented", "ipfrag", "fragflag"],
  label: ["label", "attackcat", "attackcategory", "class", "category", "detailedlabel"],
};

export interface SchemaMap {
  columns: string[];
  mapping: Record<string, number>; // internal field -> column index (-1 if absent)
  dataset: string;
  matched: number;
}

export function detectSchema(header: string[]): SchemaMap {
  const normed = header.map(norm);
  const mapping: Record<string, number> = {};
  let matched = 0;
  for (const field of Object.keys(SYNONYMS)) {
    const idx = normed.findIndex((h) => SYNONYMS[field].includes(h));
    mapping[field] = idx;
    if (idx >= 0) matched++;
  }
  return { columns: header, mapping, dataset: guessDataset(normed), matched };
}

function guessDataset(normed: string[]): string {
  const s = new Set(normed);
  if (s.has("attackcat") || s.has("sttl")) return "UNSW-NB15";
  if (s.has("id.origh") || s.has("conn_state") || s.has("detailedlabel")) return "CTU-13 / Zeek";
  if (normed.some((h) => h.includes("flowiat"))) return "CIC-IDS / CICIoT";
  return "Generic flow CSV";
}

function toNum(v: string | undefined): number {
  if (v == null) return 0;
  const n = Number(String(v).trim());
  return Number.isFinite(n) ? n : 0;
}

// Parse a raw TCP flags token like "SYN,ACK" or "0x02" or Zeek "S0" heuristically.
function parseFlagToken(tok: string): Partial<Flow> {
  const t = tok.toUpperCase();
  const f: Partial<Flow> = {};
  if (/0X/.test(t)) {
    const bits = parseInt(t, 16);
    return { fin: bits & 1, syn: (bits >> 1) & 1, rst: (bits >> 2) & 1, psh: (bits >> 3) & 1, ack: (bits >> 4) & 1, urg: (bits >> 5) & 1 };
  }
  f.syn = /S/.test(t) ? 1 : 0;
  f.ack = /A|SF|ESTAB/.test(t) ? 1 : 0;
  f.fin = /F/.test(t) ? 1 : 0;
  f.rst = /R/.test(t) ? 1 : 0;
  return f;
}

/** Minimal RFC-4180-ish CSV splitter (handles quoted fields with commas). */
export function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else {
      if (c === '"') q = true;
      else if (c === ",") { out.push(cur); cur = ""; }
      else cur += c;
    }
  }
  out.push(cur);
  return out;
}

export interface ParseResult {
  flows: Flow[];
  schema: SchemaMap;
  rows: number;
  skipped: number;
}

export function parseCsv(text: string, opts: { baseTs?: number } = {}): ParseResult {
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length < 2) throw new Error("CSV must contain a header row and at least one data row.");
  const header = splitCsvLine(lines[0]);
  const schema = detectSchema(header);
  if (schema.matched < 3) {
    throw new Error(
      `Unrecognised schema: only ${schema.matched} known columns matched. Provide a flow CSV with IP/port/flag columns.`
    );
  }
  const m = schema.mapping;
  const base = opts.baseTs ?? Date.now();
  const flows: Flow[] = [];
  let skipped = 0;
  let synthTs = 0;
  for (let i = 1; i < lines.length; i++) {
    const c = splitCsvLine(lines[i]);
    if (c.length < 2) { skipped++; continue; }
    const get = (f: string): string | undefined => (m[f] >= 0 ? c[m[f]] : undefined);

    let ts = m.ts >= 0 ? parseTs(get("ts")) : NaN;
    if (!Number.isFinite(ts)) ts = base + synthTs++ * 1000; // synthesise a monotonic clock

    const flags = get("flags");
    const flagBits = flags ? parseFlagToken(flags) : {};

    const bytes = toNum(get("bytes"));
    const bwd = toNum(get("bwdBytes"));
    const label = (get("label") || "").trim();
    const dur = toNum(get("durationMs"));

    flows.push({
      ts,
      srcIp: (get("srcIp") || "0.0.0.0").trim(),
      dstIp: (get("dstIp") || "0.0.0.0").trim(),
      srcPort: toNum(get("srcPort")),
      dstPort: toNum(get("dstPort")),
      protocol: (get("protocol") || "TCP").trim().toUpperCase().replace(/^6$/, "TCP").replace(/^17$/, "UDP"),
      syn: m.syn >= 0 ? toNum(get("syn")) : flagBits.syn ?? 0,
      ack: m.ack >= 0 ? toNum(get("ack")) : flagBits.ack ?? 0,
      fin: m.fin >= 0 ? toNum(get("fin")) : flagBits.fin ?? 0,
      rst: m.rst >= 0 ? toNum(get("rst")) : flagBits.rst ?? 0,
      psh: m.psh >= 0 ? toNum(get("psh")) : flagBits.psh ?? 0,
      urg: m.urg >= 0 ? toNum(get("urg")) : flagBits.urg ?? 0,
      bytes,
      packets: toNum(get("packets")) || 1,
      durationMs: dur > 1e7 ? dur / 1000 : dur, // some sets use microseconds
      iatMean: toNum(get("iatMean")),
      iatVar: toNum(get("iatVar")),
      iatMax: toNum(get("iatMax")),
      ttl: m.ttl >= 0 ? toNum(get("ttl")) : undefined,
      ttlVar: m.ttlVar >= 0 ? toNum(get("ttlVar")) : undefined,
      windowSize: m.windowSize >= 0 ? toNum(get("windowSize")) : undefined,
      retrans: m.retrans >= 0 ? toNum(get("retrans")) : undefined,
      fragmented: m.fragmented >= 0 ? toNum(get("fragmented")) : undefined,
      bwdBytes: bwd,
      label: label || undefined,
    });
  }
  if (flows.length === 0) throw new Error("No valid data rows parsed.");
  flows.sort((a, b) => a.ts - b.ts);
  return { flows, schema, rows: flows.length, skipped };
}

function parseTs(v: string | undefined): number {
  if (!v) return NaN;
  const s = v.trim();
  const n = Number(s);
  if (Number.isFinite(n)) {
    if (n > 1e15) return n / 1000; // microseconds
    if (n > 1e12) return n; // ms
    if (n > 1e9) return n * 1000; // seconds
    return n; // relative
  }
  const d = Date.parse(s);
  return Number.isFinite(d) ? d : NaN;
}

/** Heuristic: does a flow's label denote an attack? */
export function isAttackLabel(label: string | undefined): boolean {
  if (!label) return false;
  const l = label.trim().toLowerCase();
  return l !== "" && l !== "benign" && l !== "normal" && l !== "background" && l !== "0" && l !== "-";
}
