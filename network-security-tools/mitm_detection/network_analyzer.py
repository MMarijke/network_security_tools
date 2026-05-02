"""
network_analyzer.py - Network Traffic Analyser
CSM060 Information Security

Comprehensive PCAP analysis tool covering:
  - Traffic statistics and protocol distribution
  - HTTPS / TLS pattern analysis
  - Data exfiltration heuristics
  - JSON and text output

Usage:
    python network_analyzer.py <pcap_file>
    python network_analyzer.py <pcap_file> -o report.txt
    python network_analyzer.py <pcap_file> --json
    python network_analyzer.py <pcap_file> --internal 192.168.0.0/16
"""

from scapy.all import rdpcap, IP, TCP, UDP, ARP, Ether, ICMP, Raw
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import ipaddress
import json
import sys
import os


# ── Defaults ───────────────────────────────────────────────────────────────

# RFC 1918 private ranges used to classify internal vs external traffic.
# Can be overridden via --internal CLI flag.
DEFAULT_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Thresholds
HTTPS_VOLUME_THRESHOLD  = 50   # packets from a single source before flagging
SSL_HANDSHAKE_THRESHOLD = 5    # handshakes per source before flagging
EXFIL_BYTE_THRESHOLD    = 5000 # outbound bytes before flagging potential exfiltration
LARGE_PACKET_BYTES      = 1000

TLS_HANDSHAKE_BYTE = 0x16      # first byte of a TLS record
TLS_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0b: "Certificate",
    0x0c: "ServerKeyExchange",
    0x0e: "ServerHelloDone",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
}


# ── Helper ─────────────────────────────────────────────────────────────────

def _is_internal(ip_str: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in nets)
    except ValueError:
        return False


def _ts(epoch) -> str:
    try:
        return str(datetime.fromtimestamp(float(epoch)))
    except Exception:
        return "unknown"


def _serialisable(obj):
    if isinstance(obj, (datetime, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(obj)
    raise TypeError(f"Not serialisable: {type(obj)}")


# ── Analyser ───────────────────────────────────────────────────────────────

class NetworkAnalyzer:
    """
    Single-pass PCAP analyser. Call load_pcap() then analyse().
    Results are stored in self.summary and self.suspicious_activities.
    """

    def __init__(self, internal_nets=None):
        self.internal_nets = internal_nets or DEFAULT_INTERNAL_NETS
        self.packets = []
        self.summary = {}
        self.suspicious_activities = []
        self._https_analysis = {}
        self._exfil_analysis = {}

    # ── Loading ────────────────────────────────────────────────────────────

    def load_pcap(self, file_path: str) -> None:
        if not os.path.exists(file_path):
            sys.exit(f"[ERROR] File not found: {file_path}")
        print(f"Loading: {file_path}")
        try:
            self.packets = rdpcap(file_path)
            print(f"Loaded {len(self.packets):,} packets")
        except Exception as e:
            sys.exit(
                f"[ERROR] Could not read PCAP: {e}\n"
                f"Tip: run  python pcap_repair.py \"{file_path}\"  to attempt repair."
            )

    # ── Analysis ───────────────────────────────────────────────────────────

    def analyse(self) -> dict:
        """Run all analysis passes. Returns the full summary dict."""
        self._basic_stats()
        self._https_and_tls()
        self._data_exfiltration()
        return self.summary

    def _basic_stats(self) -> None:
        protocols  = Counter()
        unique_ips = set()
        unique_macs = set()
        conversations = defaultdict(int)
        sizes  = []
        times  = []

        for pkt in self.packets:
            try:
                sizes.append(len(pkt))
                if hasattr(pkt, "time"):
                    times.append(float(pkt.time))

                if pkt.haslayer(Ether):
                    unique_macs.add(pkt[Ether].src)
                    unique_macs.add(pkt[Ether].dst)

                if pkt.haslayer(IP):
                    src, dst = pkt[IP].src, pkt[IP].dst
                    unique_ips.update([src, dst])
                    conversations[f"{src} → {dst}"] += 1

                    if pkt.haslayer(TCP):
                        protocols["TCP"] += 1
                    elif pkt.haslayer(UDP):
                        protocols["UDP"] += 1
                    elif pkt.haslayer(ICMP):
                        protocols["ICMP"] += 1
                    else:
                        protocols["Other IP"] += 1
                elif pkt.haslayer(ARP):
                    protocols["ARP"] += 1
                else:
                    protocols["Non-IP"] += 1
            except Exception as e:
                print(f"[WARN] Packet skipped in stats pass: {e}")

        n = len(self.packets)
        duration = (max(times) - min(times)) if len(times) >= 2 else 0.0
        start_dt = _ts(min(times)) if times else "N/A"
        end_dt   = _ts(max(times)) if times else "N/A"

        self.summary["basic"] = {
            "total_packets":    n,
            "start_time":       start_dt,
            "end_time":         end_dt,
            "duration_seconds": round(duration, 3),
            "packet_rate":      round(n / duration, 3) if duration > 0 else 0,
            "avg_packet_size":  round(sum(sizes) / n, 2) if n else 0,
            "min_packet_size":  min(sizes) if sizes else 0,
            "max_packet_size":  max(sizes) if sizes else 0,
            "total_bytes":      sum(sizes),
            "unique_ips":       sorted(unique_ips),
            "unique_macs":      sorted(unique_macs),
            "protocols":        dict(protocols),
            "top_conversations": dict(Counter(conversations).most_common(10)),
        }

    def _https_and_tls(self) -> None:
        """
        Identify HTTPS (TCP/443) traffic and TLS handshake packets.

        MITM indicators flagged (as *candidates* requiring manual verification):
          - High packet volume from a single source over port 443
          - Elevated number of TLS handshakes per source (may indicate
            repeated certificate rejection or proxy re-negotiation)

        Note: volume-based indicators alone do NOT confirm a MITM attack.
        Certificate inspection (e.g. with Wireshark or openssl s_client)
        is required to confirm interception.
        """
        https_pkts = []         # list of dicts
        tls_handshakes = []     # list of dicts

        for pkt in self.packets:
            try:
                # Guard: must have both IP and TCP layers
                if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                    continue

                src_ip  = pkt[IP].src
                dst_ip  = pkt[IP].dst
                sport   = pkt[TCP].sport
                dport   = pkt[TCP].dport

                if dport == 443 or sport == 443:
                    https_pkts.append({
                        "timestamp": _ts(pkt.time),
                        "src_ip":   src_ip,
                        "dst_ip":   dst_ip,
                        "src_port": sport,
                        "dst_port": dport,
                        "flags":    str(pkt[TCP].flags),
                        "size":     len(pkt),
                    })

                # TLS record detection (byte 0 = 0x16 → Handshake)
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    if len(payload) > 5 and payload[0] == TLS_HANDSHAKE_BYTE:
                        hs_type = payload[5] if len(payload) > 5 else None
                        tls_handshakes.append({
                            "timestamp":      _ts(pkt.time),
                            "src_ip":         src_ip,
                            "dst_ip":         dst_ip,
                            "handshake_type": TLS_HANDSHAKE_TYPES.get(hs_type, f"0x{hs_type:02x}" if hs_type else "unknown"),
                        })
            except Exception as e:
                print(f"[WARN] Packet skipped in HTTPS pass: {e}")

        # Aggregate by source IP
        vol_by_src   = Counter(p["src_ip"] for p in https_pkts)
        bytes_by_src = defaultdict(int)
        for p in https_pkts:
            bytes_by_src[p["src_ip"]] += p["size"]

        hs_by_src = Counter(h["src_ip"] for h in tls_handshakes)

        indicators = []

        # Flag high-volume sources
        for ip, count in vol_by_src.items():
            if count > HTTPS_VOLUME_THRESHOLD:
                indicators.append({
                    "type":        "High Volume HTTPS Traffic",
                    "source_ip":   ip,
                    "packet_count": count,
                    "total_bytes": bytes_by_src[ip],
                    "severity":    "MEDIUM",
                    "note":        (
                        "Candidate indicator only — high packet count on port 443 "
                        "is not confirmation of MITM. Verify via certificate inspection."
                    ),
                    "description": f"High HTTPS volume: {count} packets from {ip}",
                })

        # Flag elevated TLS handshake counts
        for ip, count in hs_by_src.items():
            if count > SSL_HANDSHAKE_THRESHOLD:
                indicators.append({
                    "type":             "Elevated TLS Handshakes",
                    "source_ip":        ip,
                    "handshake_count":  count,
                    "severity":         "MEDIUM",
                    "note":             (
                        "Multiple handshakes may indicate certificate rejection loops "
                        "or a proxy re-negotiating separate TLS sessions — a known "
                        "MITM proxy pattern. Manual certificate validation required."
                    ),
                    "description": f"Elevated TLS handshakes ({count}) from {ip}",
                })

        for ind in indicators:
            self.suspicious_activities.append(ind)

        self._https_analysis = {
            "https_packet_count":    len(https_pkts),
            "tls_handshake_count":   len(tls_handshakes),
            "volume_by_source":      dict(vol_by_src),
            "bytes_by_source":       dict(bytes_by_src),
            "handshakes_by_source":  dict(hs_by_src),
            "mitm_indicators":       indicators,
        }
        self.summary["https"] = self._https_analysis

    def _data_exfiltration(self) -> None:
        """
        Heuristic check for large outbound data transfers.

        'Outbound' is defined as traffic from an RFC 1918 address to a
        non-RFC 1918 address. The internal subnet set is configurable via
        --internal so that captures using non-standard addressing are handled
        correctly.
        """
        outbound  = defaultdict(int)   # src_ip → bytes
        inbound   = defaultdict(int)   # dst_ip → bytes
        large_pkts = []

        for pkt in self.packets:
            try:
                if not pkt.haslayer(IP):
                    continue

                src = pkt[IP].src
                dst = pkt[IP].dst
                size = len(pkt)

                src_internal = _is_internal(src, self.internal_nets)
                dst_internal = _is_internal(dst, self.internal_nets)

                if src_internal and not dst_internal:
                    outbound[src] += size
                    if size > LARGE_PACKET_BYTES:
                        large_pkts.append({
                            "timestamp": _ts(pkt.time),
                            "src_ip":    src,
                            "dst_ip":    dst,
                            "size":      size,
                            "direction": "outbound",
                        })
                elif dst_internal and not src_internal:
                    inbound[dst] += size

            except Exception as e:
                print(f"[WARN] Packet skipped in exfil pass: {e}")

        candidates = [
            {"source_ip": ip, "total_bytes": total}
            for ip, total in outbound.items()
            if total > EXFIL_BYTE_THRESHOLD
        ]

        for c in candidates:
            self.suspicious_activities.append({
                "type":        "Potential Data Exfiltration",
                "source_ip":   c["source_ip"],
                "total_bytes": c["total_bytes"],
                "severity":    "HIGH",
                "note":        (
                    "Threshold-based heuristic. Review destination IP reputation "
                    "and payload content to confirm exfiltration."
                ),
                "description": (
                    f"Large outbound transfer: {c['total_bytes']:,} bytes "
                    f"from {c['source_ip']}"
                ),
            })

        self._exfil_analysis = {
            "outbound_flows":          dict(outbound),
            "inbound_flows":           dict(inbound),
            "large_packet_count":      len(large_pkts),
            "exfiltration_candidates": candidates,
        }
        self.summary["exfiltration"] = self._exfil_analysis

    # ── Formatted output ───────────────────────────────────────────────────

    def print_report(self) -> None:
        b = self.summary.get("basic", {})
        h = self.summary.get("https", {})
        e = self.summary.get("exfiltration", {})

        print("\n" + "=" * 62)
        print("NETWORK TRAFFIC ANALYSIS")
        print("=" * 62)
        print(f"Capture period   : {b.get('start_time')} → {b.get('end_time')}")
        print(f"Duration         : {b.get('duration_seconds')} s")
        print(f"Total packets    : {b.get('total_packets'):,}")
        print(f"Total bytes      : {b.get('total_bytes'):,}")
        print(f"Avg packet size  : {b.get('avg_packet_size')} B")
        print(f"Packet rate      : {b.get('packet_rate')} pkt/s")
        print(f"Unique IPs       : {len(b.get('unique_ips', []))}")
        print(f"Unique MACs      : {len(b.get('unique_macs', []))}")

        print("\nIP addresses:")
        for ip in b.get("unique_ips", []):
            print(f"  {ip}")

        print("\nProtocol distribution:")
        total = b.get("total_packets", 1)
        for proto, count in sorted(b.get("protocols", {}).items(),
                                   key=lambda x: -x[1]):
            print(f"  {proto:<12} {count:>5}  ({count/total*100:.1f}%)")

        print("\nTop conversations:")
        for convo, count in list(b.get("top_conversations", {}).items())[:5]:
            print(f"  {convo}  [{count} pkts]")

        print("\n" + "=" * 62)
        print("HTTPS / TLS ANALYSIS")
        print("=" * 62)
        print(f"HTTPS packets    : {h.get('https_packet_count', 0):,}")
        print(f"TLS handshakes   : {h.get('tls_handshake_count', 0):,}")

        if h.get("volume_by_source"):
            print("\nHTTPS volume by source:")
            for ip, count in sorted(h["volume_by_source"].items(),
                                    key=lambda x: -x[1]):
                print(f"  {ip:<18} {count:>5} packets  "
                      f"{h['bytes_by_source'].get(ip, 0):,} bytes")

        if h.get("handshakes_by_source"):
            print("\nTLS handshakes by source:")
            for ip, count in sorted(h["handshakes_by_source"].items(),
                                    key=lambda x: -x[1]):
                print(f"  {ip:<18} {count:>3} handshakes")

        print("\n" + "=" * 62)
        print("DATA EXFILTRATION HEURISTICS")
        print("=" * 62)
        print(f"Large outbound packets (>{LARGE_PACKET_BYTES} B): "
              f"{e.get('large_packet_count', 0)}")

        if e.get("outbound_flows"):
            print("\nOutbound data by source:")
            for ip, b_ in sorted(e["outbound_flows"].items(),
                                  key=lambda x: -x[1]):
                print(f"  {ip:<18} {b_:>10,} bytes outbound")

        if e.get("inbound_flows"):
            print("\nInbound data by destination:")
            for ip, b_ in sorted(e["inbound_flows"].items(),
                                  key=lambda x: -x[1]):
                print(f"  {ip:<18} {b_:>10,} bytes inbound")

        print("\n" + "=" * 62)
        print("SECURITY FINDINGS")
        print("=" * 62)
        acts = self.suspicious_activities
        if not acts:
            print("✓ No suspicious activities detected.")
        else:
            print(f"⚠  {len(acts)} finding(s):\n")
            for act in acts:
                sev = act.get("severity", "?")
                print(f"  [{sev}] {act['type']}")
                print(f"         {act['description']}")
                if "note" in act:
                    print(f"         Note: {act['note']}")
                print()

    def save_text_report(self, path: str) -> None:
        # Redirect print output to file via basic string capture
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.print_report()
        with open(path, "w") as f:
            f.write(f"NETWORK SECURITY ANALYSIS REPORT\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            f.write(buf.getvalue())
        print(f"Text report saved to: {path}")

    def save_json_report(self, path: str) -> None:
        payload = {
            "generated":              datetime.now().isoformat(),
            "summary":                self.summary,
            "suspicious_activities":  self.suspicious_activities,
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=_serialisable)
        print(f"JSON report saved to: {path}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a PCAP for HTTPS MITM indicators and data exfiltration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python network_analyzer.py capture.pcap\n"
            "  python network_analyzer.py capture.pcap -o report.txt\n"
            "  python network_analyzer.py capture.pcap --json -o results.json\n"
            "  python network_analyzer.py capture.pcap --internal 172.16.0.0/12\n"
        ),
    )
    parser.add_argument("pcap_file", help="PCAP file to analyse")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save report to file")
    parser.add_argument("--json", action="store_true",
                        help="Save report as JSON instead of plain text")
    parser.add_argument("--internal", metavar="CIDR",
                        help="Override internal subnet (default: RFC 1918). "
                             "E.g. --internal 10.99.0.0/16")
    args = parser.parse_args()

    internal_nets = DEFAULT_INTERNAL_NETS
    if args.internal:
        try:
            internal_nets = [ipaddress.ip_network(args.internal, strict=False)]
            print(f"Internal network set to: {args.internal}")
        except ValueError:
            sys.exit(f"[ERROR] Invalid CIDR notation: {args.internal}")

    analyzer = NetworkAnalyzer(internal_nets=internal_nets)
    analyzer.load_pcap(args.pcap_file)
    analyzer.analyse()
    analyzer.print_report()

    if args.output:
        if args.json:
            analyzer.save_json_report(args.output)
        else:
            analyzer.save_text_report(args.output)
    elif args.json:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        analyzer.save_json_report(f"network_analysis_{ts}.json")


if __name__ == "__main__":
    main()
