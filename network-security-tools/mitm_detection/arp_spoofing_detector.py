"""
arp_spoofing_detector.py - ARP Spoofing Detection Tool
CSM060 Information Security

Detects ARP spoofing / Man-in-the-Middle attacks by tracking IP-to-MAC
bindings in ARP reply packets and flagging IPs that claim more than one
MAC address within a capture window.

Usage:
    python arp_spoofing_detector.py <pcap_file>
    python arp_spoofing_detector.py <pcap_file> --verbose
    python arp_spoofing_detector.py <pcap_file> -o report.txt
    python arp_spoofing_detector.py <pcap_file> --json
"""

from scapy.all import rdpcap, ARP, Ether
from collections import defaultdict, namedtuple
from datetime import datetime
from typing import Dict, Set, List
import argparse
import sys
import json


# ── Data types ─────────────────────────────────────────────────────────────

# Lightweight record for each unique (IP, MAC) binding observed
Binding = namedtuple("Binding", ["ip", "mac", "first_seen", "last_seen", "packet_count"])


# ── Detector ───────────────────────────────────────────────────────────────

class ARPSpoofingDetector:
    """
    Tracks IP-to-MAC address bindings from ARP reply packets.

    Detection principle: in a healthy network each IP address maps to
    exactly one MAC. When a second MAC begins claiming the same IP the
    binding table is inconsistent — a strong indicator of ARP spoofing.

    Confidence scoring
    ------------------
    A score between 0 and 1 reflects how actively the conflict is being
    maintained:

        score = min_frequency / max_frequency

    A score near 1.0 means both MACs are sending at similar rates —
    consistent with live bidirectional poisoning. A low score means one
    MAC heavily dominates, which may indicate a legitimate network change
    (e.g. NIC replacement) rather than an active attack.
    """

    def __init__(self):
        # ip  → set of MAC strings
        self._ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        # (ip, mac) → packet count
        self._counts: Dict[tuple, int] = defaultdict(int)
        # (ip, mac) → first and last timestamp seen
        self._first_seen: Dict[tuple, float] = {}
        self._last_seen: Dict[tuple, float] = {}

    # ── Packet ingestion ───────────────────────────────────────────────────

    def process_packet(self, packet) -> None:
        """Ingest one packet. Only ARP replies (op=2) are processed."""
        if not packet.haslayer(ARP):
            return
        arp = packet[ARP]
        if arp.op != 2:          # ignore ARP requests
            return

        ip  = arp.psrc
        mac = arp.hwsrc.lower()  # normalise to lowercase for consistent keying
        key = (ip, mac)
        ts  = float(packet.time) if hasattr(packet, "time") else 0.0

        self._ip_to_macs[ip].add(mac)
        self._counts[key] += 1

        if key not in self._first_seen:
            self._first_seen[key] = ts
        self._last_seen[key] = ts

    def process_packets(self, packets) -> None:
        for i, pkt in enumerate(packets):
            try:
                self.process_packet(pkt)
            except Exception as e:
                print(f"[WARN] Packet {i} skipped: {e}")

    # ── Detection ──────────────────────────────────────────────────────────

    def suspicious_ips(self) -> Dict[str, Set[str]]:
        """Return IPs that have been claimed by more than one MAC address."""
        return {ip: macs for ip, macs in self._ip_to_macs.items()
                if len(macs) > 1}

    def confidence_score(self, ip: str) -> float:
        """
        Return a 0–1 confidence score for the conflict on a given IP.
        Returns 0.0 if there is no conflict or no packet data.
        """
        macs = self._ip_to_macs.get(ip, set())
        if len(macs) < 2:
            return 0.0

        counts = [self._counts.get((ip, mac), 0) for mac in macs]
        max_c = max(counts)
        min_c = min(counts)

        if max_c == 0:
            return 0.0

        return round(min_c / max_c, 3)

    def bindings_for(self, ip: str) -> List[Binding]:
        """Return all Binding records for a given IP, sorted by packet count."""
        result = []
        for mac in self._ip_to_macs.get(ip, set()):
            key = (ip, mac)
            count = self._counts.get(key, 0)
            first = self._first_seen.get(key, 0.0)
            last  = self._last_seen.get(key, 0.0)
            result.append(Binding(ip=ip, mac=mac,
                                  first_seen=first, last_seen=last,
                                  packet_count=count))
        return sorted(result, key=lambda b: b.packet_count, reverse=True)

    # ── Reporting ──────────────────────────────────────────────────────────

    def _ts(self, epoch: float) -> str:
        try:
            return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"

    def _confidence_label(self, score: float) -> str:
        if score >= 0.7:
            return "HIGH (active bidirectional poisoning likely)"
        if score >= 0.3:
            return "MEDIUM (possible attack or network change)"
        return "LOW (dominant MAC — may be legitimate network change)"

    def build_report(self, verbose: bool = False) -> List[str]:
        lines = []
        suspicious = self.suspicious_ips()

        lines += [
            "=" * 62,
            "ARP SPOOFING DETECTION REPORT",
            "=" * 62,
            f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Suspicious IPs detected : {len(suspicious)}",
            "",
        ]

        if not suspicious:
            lines.append("✓ No ARP spoofing patterns detected.")
            return lines

        for ip, macs in sorted(suspicious.items()):
            score = self.confidence_score(ip)
            label = self._confidence_label(score)
            bindings = self.bindings_for(ip)

            lines += [
                f"  ⚠ CONFLICT DETECTED — IP: {ip}",
                f"    Conflicting MACs   : {len(macs)}",
                f"    Confidence score   : {score:.3f}  [{label}]",
                "    Bindings:",
            ]
            for b in bindings:
                lines.append(
                    f"      {b.mac}  "
                    f"({b.packet_count} pkt(s)  "
                    f"first: {self._ts(b.first_seen)}  "
                    f"last: {self._ts(b.last_seen)})"
                )
            lines.append("")

        if verbose:
            lines += ["", "── Full ARP binding table ──"]
            for ip in sorted(self._ip_to_macs):
                for b in self.bindings_for(ip):
                    lines.append(
                        f"  {ip:16s}  {b.mac}  "
                        f"{b.packet_count} pkt(s)"
                    )

        return lines

    def to_dict(self) -> dict:
        """Return analysis results as a JSON-serialisable dict."""
        suspicious = self.suspicious_ips()
        results = []
        for ip in sorted(suspicious):
            score = self.confidence_score(ip)
            results.append({
                "ip": ip,
                "conflict_mac_count": len(suspicious[ip]),
                "confidence_score": score,
                "confidence_label": self._confidence_label(score),
                "bindings": [
                    {
                        "mac": b.mac,
                        "packet_count": b.packet_count,
                        "first_seen": self._ts(b.first_seen),
                        "last_seen":  self._ts(b.last_seen),
                    }
                    for b in self.bindings_for(ip)
                ],
            })
        return {
            "generated": datetime.now().isoformat(),
            "suspicious_ip_count": len(suspicious),
            "detections": results,
        }


# ── I/O helpers ────────────────────────────────────────────────────────────

def load_pcap(file_path: str):
    """Load and return packets from a PCAP file, with clear error messages."""
    import os
    if not os.path.exists(file_path):
        sys.exit(f"[ERROR] File not found: {file_path}")
    print(f"Loading: {file_path}")
    try:
        packets = rdpcap(file_path)
        print(f"Loaded {len(packets):,} packets")
        return packets
    except Exception as e:
        sys.exit(
            f"[ERROR] Could not read PCAP: {e}\n"
            f"Tip: run  python pcap_repair.py \"{file_path}\"  to attempt repair."
        )


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detect ARP spoofing / MITM attacks in a PCAP capture.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python arp_spoofing_detector.py traffic.pcap\n"
            "  python arp_spoofing_detector.py traffic.pcap --verbose\n"
            "  python arp_spoofing_detector.py traffic.pcap --json -o report.json\n"
        ),
    )
    parser.add_argument("pcap_file", help="PCAP file to analyse")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Include full ARP binding table in output")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save report to file")
    parser.add_argument("--json", action="store_true",
                        help="Output report as JSON (implies --output if -o not set)")
    args = parser.parse_args()

    packets  = load_pcap(args.pcap_file)
    detector = ARPSpoofingDetector()
    detector.process_packets(packets)

    # ── Output ──
    if args.json:
        payload = json.dumps(detector.to_dict(), indent=2)
        print(payload)
        out_path = args.output or f"arp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_path, "w") as f:
            f.write(payload)
        print(f"\nJSON report saved to: {out_path}")
    else:
        lines = detector.build_report(verbose=args.verbose)
        output = "\n".join(lines)
        print(output)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"\nReport saved to: {args.output}")

    suspicious = detector.suspicious_ips()
    sys.exit(1 if suspicious else 0)


if __name__ == "__main__":
    main()
