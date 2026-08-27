"""Isolated analysis worker. Invoked as a subprocess by the API so that a
malformed / adversarial capture that crashes or hangs the parser can never take
down the API process — the subprocess is killed on timeout and the request fails
cleanly. Reads a file path + kind, prints the analysis as JSON on stdout.

  python -m backend.runner <path> <csv|pcap>
"""
from __future__ import annotations

import json
import socket
import struct
import sys
from collections import defaultdict

_HEADER = ["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
           "SYN Count", "ACK Count", "FIN Count", "RST Count", "PSH Count", "URG Count",
           "Total Bytes", "Total Bwd Bytes", "Total Packets", "Flow Duration",
           "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "TTL",
           "Init Win Bytes Forward", "Retrans", "Frag", "Label"]


def _new_flow():
    return {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0,
            "bytes": 0, "pkts": 0, "t0": None, "tN": None, "ttl": 0, "n_ttl": 0,
            "win": 0, "n_win": 0, "retrans": 0, "frag": 0, "seqs": set()}


def _accumulate(flows, ts, src, dst, sport, dport, proto, ttl, frag,
                tcp_flags, window, seq, payload_len, wire_len):
    key = (src, dst, sport, dport, proto)
    f = flows[key]
    f["bytes"] += int(wire_len); f["pkts"] += 1
    f["t0"] = ts if f["t0"] is None else min(f["t0"], ts)
    f["tN"] = ts if f["tN"] is None else max(f["tN"], ts)
    f["ttl"] += int(ttl); f["n_ttl"] += 1
    if frag:
        f["frag"] += 1
    if proto == "TCP" and tcp_flags is not None:
        f["fin"] += tcp_flags & 1; f["syn"] += (tcp_flags >> 1) & 1; f["rst"] += (tcp_flags >> 2) & 1
        f["psh"] += (tcp_flags >> 3) & 1; f["ack"] += (tcp_flags >> 4) & 1; f["urg"] += (tcp_flags >> 5) & 1
        f["win"] += int(window); f["n_win"] += 1
        if payload_len > 0:                       # duplicate data-seq ⇒ retransmission
            if seq in f["seqs"]:
                f["retrans"] += 1
            else:
                f["seqs"].add(seq)


def _parse_pure(pcap_path: str, flows: dict) -> int:
    """Dependency-free parser for classic libpcap files (Ethernet/IPv4, TCP/UDP).
    Extracts TTL, TCP window, IP fragment flags, payload length and TCP seq — the
    packet-level fields the feature pipeline needs. Returns packet count, or -1 if
    the file is not a classic pcap (caller then tries scapy for pcapng/others)."""
    with open(pcap_path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return -1
        magic = gh[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
        else:
            return -1                              # not classic pcap (maybe pcapng)
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        n = 0
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rh)
            data = fh.read(incl)
            if len(data) < incl:
                break
            n += 1
            if n > 2_000_000:
                break
            ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
            off = 14 if linktype == 1 else 0        # Ethernet header, else raw IP
            if linktype == 1:
                if len(data) < 14:
                    continue
                eth = struct.unpack(">H", data[12:14])[0]
                while eth == 0x8100 and len(data) >= off + 4:   # VLAN tag
                    eth = struct.unpack(">H", data[off + 2:off + 4])[0]
                    off += 4
                if eth != 0x0800:                   # only IPv4
                    continue
            if len(data) < off + 20:
                continue
            ihl = (data[off] & 0x0F) * 4
            ttl = data[off + 8]
            proto_num = data[off + 9]
            flags_frag = struct.unpack(">H", data[off + 6:off + 8])[0]
            frag = 1 if (flags_frag & 0x2000) or (flags_frag & 0x1FFF) else 0   # MF or offset>0
            src = socket.inet_ntoa(data[off + 12:off + 16])
            dst = socket.inet_ntoa(data[off + 16:off + 20])
            l4 = off + ihl
            total_len = struct.unpack(">H", data[off + 2:off + 4])[0]
            if proto_num == 6 and len(data) >= l4 + 20:            # TCP
                sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
                seq = struct.unpack(">I", data[l4 + 4:l4 + 8])[0]
                doff = (data[l4 + 12] >> 4) * 4
                flags = data[l4 + 13]
                window = struct.unpack(">H", data[l4 + 14:l4 + 16])[0]
                payload = max(0, total_len - ihl - doff)
                _accumulate(flows, ts, src, dst, sport, dport, "TCP", ttl, frag, flags, window, seq, payload, len(data))
            elif proto_num == 17 and len(data) >= l4 + 8:          # UDP
                sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
                _accumulate(flows, ts, src, dst, sport, dport, "UDP", ttl, frag, None, 0, 0, 0, len(data))
            else:
                _accumulate(flows, ts, src, dst, 0, 0, "OTHER", ttl, frag, None, 0, 0, 0, len(data))
        return n


def _parse_scapy(pcap_path: str, flows: dict) -> int:
    """Fallback for pcapng / non-Ethernet captures when scapy is available."""
    from scapy.all import PcapReader, TCP, UDP, IP  # type: ignore
    n = 0
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            n += 1
            if n > 2_000_000:
                break
            if IP not in pkt:
                continue
            ip = pkt[IP]
            frag = 1 if (int(ip.flags) & 0x1) or int(ip.frag) else 0   # MF bit or offset
            if TCP in pkt:
                tcp = pkt[TCP]
                _accumulate(flows, float(pkt.time), ip.src, ip.dst, int(tcp.sport), int(tcp.dport),
                            "TCP", int(ip.ttl), frag, int(tcp.flags), int(tcp.window),
                            int(tcp.seq), len(tcp.payload), len(pkt))
            elif UDP in pkt:
                udp = pkt[UDP]
                _accumulate(flows, float(pkt.time), ip.src, ip.dst, int(udp.sport), int(udp.dport),
                            "UDP", int(ip.ttl), frag, None, 0, 0, 0, len(pkt))
            else:
                _accumulate(flows, float(pkt.time), ip.src, ip.dst, 0, 0, "OTHER",
                            int(ip.ttl), frag, None, 0, 0, 0, len(pkt))
    return n


def pcap_to_csv(pcap_path: str, csv_path: str) -> None:
    """Convert a raw PCAP to the internal flow-CSV schema. Packets are parsed at the
    packet level (TTL, TCP window, IP fragment flags, payload size, retransmissions)
    and aggregated into 5-tuple flows. Uses a dependency-free classic-pcap parser;
    falls back to scapy for pcapng / exotic link types when installed."""
    import csv
    flows: dict = defaultdict(_new_flow)
    n = _parse_pure(pcap_path, flows)
    if n < 0:                                       # not classic pcap → try scapy
        try:
            n = _parse_scapy(pcap_path, flows)
        except Exception as e:
            raise RuntimeError(
                "Unsupported capture format (not a classic .pcap). pcapng needs scapy "
                "installed, or convert with `editcap -F libpcap in.pcapng out.pcap`."
            ) from e
    if not flows:
        raise RuntimeError("No IPv4 packets found in capture.")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(_HEADER)
        for (src, dst, sp, dp, proto), f in flows.items():
            dur = int((f["tN"] - f["t0"]) * 1000) if f["t0"] else 0
            w.writerow([int((f["t0"] or 0) * 1000), src, dst, sp, dp, proto,
                        f["syn"], f["ack"], f["fin"], f["rst"], f["psh"], f["urg"],
                        f["bytes"], 0, f["pkts"], dur, 0, 0, 0,
                        int(f["ttl"] / max(f["n_ttl"], 1)),
                        int(f["win"] / max(f["n_win"], 1)) or 65535, f["retrans"], f["frag"], "BENIGN"])


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: runner.py <path> <csv|pcap>"}))
        return 2
    path, kind = sys.argv[1], sys.argv[2]
    try:
        from backend.infer import analyze_csv
        if kind == "pcap":
            csv_path = path + ".flows.csv"
            pcap_to_csv(path, csv_path)
            path = csv_path
        result = analyze_csv(path)
        sys.stdout.write(json.dumps(result))
        return 0
    except Exception as e:
        sys.stdout.write(json.dumps({"error": str(e)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
