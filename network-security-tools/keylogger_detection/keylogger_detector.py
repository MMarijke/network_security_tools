"""
keylogger_detector.py - Keylogger Activity Detection Tool
CSM060 Information Security

Detects keylogger-like behaviour in network captures by analysing traffic
metadata — packet sizes, timing regularity, outbound asymmetry, and
destination concentration. No payload inspection is performed; the tool
works on encrypted traffic.

Usage:
    python keylogger_detector.py <pcap_file>
    python keylogger_detector.py <pcap_file> --threshold 3
    python keylogger_detector.py <pcap_file> --explain
    python keylogger_detector.py <pcap_file> --json -o report.json
    python keylogger_detector.py <pcap_file> --host 140.82.59.185
"""

from scapy.all import rdpcap, PcapReader, IP, TCP, UDP
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import ipaddress
import json
import statistics
import sys
import os


# ── Scoring constants ──────────────────────────────────────────────────────

# Each criterion's point value — sum to MAX_SCORE
SCORE_SMALL_PACKETS      = 3   # avg packet size < SMALL_PKT_THRESHOLD bytes
SCORE_HIGH_RATIO         = 2   # outbound:inbound packet ratio > RATIO_THRESHOLD
SCORE_REGULAR_TIMING     = 2   # coefficient of variation of intervals < CV_THRESHOLD
SCORE_SINGLE_DESTINATION = 2   # ≥ DEST_CONCENTRATION_PCT % traffic to one IP
SCORE_HIGH_FREQUENCY     = 1   # ≥ FREQ_THRESHOLD outbound packets

MAX_SCORE = (SCORE_SMALL_PACKETS + SCORE_HIGH_RATIO + SCORE_REGULAR_TIMING
             + SCORE_SINGLE_DESTINATION + SCORE_HIGH_FREQUENCY)   # = 10

SUSPICION_THRESHOLD      = 4   # score at which a host is flagged

SMALL_PKT_THRESHOLD      = 100   # bytes
RATIO_THRESHOLD          = 3.0
CV_THRESHOLD             = 0.3   # coefficient of variation (stdev/mean)
DEST_CONCENTRATION_PCT   = 0.70  # fraction of traffic to single destination
FREQ_THRESHOLD           = 50    # outbound packets

# RFC 1918 private ranges
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _ts(epoch) -> str:
    try:
        return str(datetime.fromtimestamp(float(epoch)))
    except Exception:
        return "N/A"


def _serialisable(obj):
    if hasattr(obj, "__str__"):
        return str(obj)
    raise TypeError


# ── Detector ───────────────────────────────────────────────────────────────

class KeyloggerDetector:
    """
    Analyses a PCAP file for hosts exhibiting keylogger-like traffic patterns.

    Detection is metadata-only (packet sizes, timing, volume ratios) and
    works on encrypted traffic. The scoring rubric is:

        +3  Average outbound packet size < 100 bytes
        +2  Outbound:inbound packet ratio > 3:1
        +2  Timing regularity: coefficient of variation < 0.3
            (CV = stdev / mean of inter-packet intervals; low CV = regular schedule)
        +2  ≥ 70% of outbound packets go to a single destination
        +1  ≥ 50 outbound packets (sustained high-frequency transmission)

    Hosts scoring ≥ 4 are flagged as suspicious.
    """

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets   = []
        # per-IP stats — populated by analyze_traffic_patterns()
        self.host_stats: dict = defaultdict(lambda: {
            "outbound_pkts":  [],    # list of {"size", "ts", "dst"}
            "inbound_pkts":   [],    # list of {"size", "ts", "src"}
            "destinations":   Counter(),
            "pkt_sizes":      [],    # outbound sizes
            "timestamps":     [],    # outbound timestamps
            "bytes_out":      0,
            "bytes_in":       0,
        })

    # ── Loading ────────────────────────────────────────────────────────────

    def load_pcap(self) -> bool:
        if not os.path.exists(self.pcap_file):
            print(f"[ERROR] File not found: {self.pcap_file}")
            return False

        print(f"Loading: {self.pcap_file}  "
              f"({os.path.getsize(self.pcap_file):,} bytes)")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets):,} packets via rdpcap")
            return True
        except Exception as e1:
            print(f"[WARN] rdpcap failed ({e1}), trying PcapReader...")

        try:
            self.packets = []
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    self.packets.append(pkt)
            print(f"Loaded {len(self.packets):,} packets via PcapReader")
            return True
        except Exception as e2:
            print(f"[ERROR] Could not read PCAP.\n"
                  f"  rdpcap error    : {e1}\n"
                  f"  PcapReader error: {e2}\n"
                  f"Tip: python pcap_repair.py \"{self.pcap_file}\"")
            return False

    # ── Traffic classification ─────────────────────────────────────────────

    def analyze_traffic_patterns(self) -> None:
        """
        Classify each IP packet as outbound or inbound using the ipaddress
        module (RFC 1918 ranges). Avoids the startswith() subnet-overlap bug
        present in prefix-string approaches.
        """
        print("Analysing traffic patterns...")

        for pkt in self.packets:
            try:
                if IP not in pkt:
                    continue

                src  = pkt[IP].src
                dst  = pkt[IP].dst
                size = len(pkt[IP])          # IP payload only
                ts   = float(pkt.time)

                src_internal = _is_internal(src)
                dst_internal = _is_internal(dst)

                # Outbound: internal → external
                if src_internal and not dst_internal:
                    s = self.host_stats[src]
                    s["outbound_pkts"].append({"size": size, "ts": ts, "dst": dst})
                    s["destinations"][dst] += 1
                    s["pkt_sizes"].append(size)
                    s["timestamps"].append(ts)
                    s["bytes_out"] += size

                # Inbound: external → internal
                elif dst_internal and not src_internal:
                    s = self.host_stats[dst]
                    s["inbound_pkts"].append({"size": size, "ts": ts, "src": src})
                    s["bytes_in"] += size

                # Internal ↔ internal — track on both sides
                elif src_internal and dst_internal:
                    self.host_stats[src]["bytes_out"] += size
                    self.host_stats[dst]["bytes_in"]  += size

            except Exception as e:
                print(f"[WARN] Packet skipped: {e}")

    # ── Periodicity ────────────────────────────────────────────────────────

    @staticmethod
    def _coefficient_of_variation(timestamps: list) -> float:
        """
        Return the coefficient of variation (stdev / mean) of inter-packet
        intervals. Low CV → regular/scheduled transmissions.

        Returns None if there are fewer than 3 samples (not enough data).
        """
        if len(timestamps) < 3:
            return None

        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i] - sorted_ts[i-1]
                     for i in range(1, len(sorted_ts))
                     if sorted_ts[i] - sorted_ts[i-1] > 0]   # exclude zero gaps

        if len(intervals) < 2:
            return None

        mean = statistics.mean(intervals)
        if mean == 0:
            return None

        return statistics.stdev(intervals) / mean

    # ── Detection ──────────────────────────────────────────────────────────

    def detect_suspicious_hosts(self, threshold: int = SUSPICION_THRESHOLD) -> list:
        """Score every host and return those at or above the threshold."""
        print("Detecting suspicious behaviour...")
        results = []

        for ip, s in self.host_stats.items():
            n_out = len(s["outbound_pkts"])
            n_in  = len(s["inbound_pkts"])

            if n_out == 0:
                continue

            avg_size = statistics.mean(s["pkt_sizes"]) if s["pkt_sizes"] else 0
            ratio    = n_out / max(n_in, 1)
            cv       = self._coefficient_of_variation(s["timestamps"])

            top_dest, top_dest_count = (
                s["destinations"].most_common(1)[0]
                if s["destinations"] else ("N/A", 0)
            )
            dest_concentration = top_dest_count / n_out if n_out else 0

            # ── Scoring ──
            score   = 0
            reasons = []

            if avg_size < SMALL_PKT_THRESHOLD:
                score += SCORE_SMALL_PACKETS
                reasons.append(
                    f"Small avg packet size ({avg_size:.1f} B < {SMALL_PKT_THRESHOLD} B) "
                    f"— consistent with keystroke-sized payloads  [+{SCORE_SMALL_PACKETS}]"
                )

            if ratio > RATIO_THRESHOLD:
                score += SCORE_HIGH_RATIO
                reasons.append(
                    f"High outbound:inbound ratio ({ratio:.1f}:1 > {RATIO_THRESHOLD}:1) "
                    f"— data exfiltration asymmetry  [+{SCORE_HIGH_RATIO}]"
                )

            if cv is not None and cv < CV_THRESHOLD:
                score += SCORE_REGULAR_TIMING
                reasons.append(
                    f"Regular transmission timing (CV={cv:.3f} < {CV_THRESHOLD}) "
                    f"— suggests scheduled/periodic exfiltration  [+{SCORE_REGULAR_TIMING}]"
                )
            elif cv is None:
                reasons.append("Timing regularity: insufficient samples to evaluate")

            if dest_concentration >= DEST_CONCENTRATION_PCT:
                score += SCORE_SINGLE_DESTINATION
                reasons.append(
                    f"Concentrated traffic: {dest_concentration:.0%} to {top_dest} "
                    f"({top_dest_count} pkts) — C&C server pattern  [+{SCORE_SINGLE_DESTINATION}]"
                )

            if n_out >= FREQ_THRESHOLD:
                score += SCORE_HIGH_FREQUENCY
                reasons.append(
                    f"High transmission frequency ({n_out} outbound packets) "
                    f"— sustained continuous activity  [+{SCORE_HIGH_FREQUENCY}]"
                )

            if score < threshold:
                continue

            ts_list = s["timestamps"]
            start   = min(ts_list) if ts_list else 0
            end     = max(ts_list) if ts_list else 0

            results.append({
                "ip":           ip,
                "score":        score,
                "max_score":    MAX_SCORE,
                "reasons":      reasons,
                "n_out":        n_out,
                "n_in":         n_in,
                "ratio":        round(ratio, 2),
                "avg_size":     round(avg_size, 1),
                "bytes_out":    s["bytes_out"],
                "bytes_in":     s["bytes_in"],
                "cv":           round(cv, 3) if cv is not None else None,
                "top_dest":     top_dest,
                "top_dest_pct": round(dest_concentration * 100, 1),
                "start_time":   _ts(start),
                "end_time":     _ts(end),
                "duration_s":   round(end - start, 1) if start and end else 0,
                "destinations": dict(s["destinations"].most_common(10)),
            })

        return sorted(results, key=lambda x: -x["score"])

    # ── Reporting ──────────────────────────────────────────────────────────

    def print_report(self, hosts: list, explain: bool = False) -> None:
        n_internal = sum(1 for ip in self.host_stats if _is_internal(ip))
        n_external = len(self.host_stats) - n_internal

        print("\n" + "=" * 72)
        print("KEYLOGGER ACTIVITY DETECTION REPORT")
        print("=" * 72)
        print(f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"PCAP file   : {self.pcap_file}")
        print(f"Packets     : {len(self.packets):,}")
        print(f"Unique IPs  : {len(self.host_stats)} "
              f"({n_internal} internal, {n_external} external)")
        print(f"Alerts      : {len(hosts)}\n")

        if explain:
            self._print_scoring_explanation()

        if not hosts:
            print("✓ No keylogger-like behaviour detected at current threshold.")
            return

        for i, h in enumerate(hosts, 1):
            print(f"SUSPICIOUS HOST #{i}  —  {h['ip']}")
            print("-" * 52)
            print(f"  Score        : {h['score']}/{h['max_score']}")
            print(f"  Period       : {h['start_time']} → {h['end_time']}  "
                  f"({h['duration_s']}s)")
            print()
            print(f"  Outbound     : {h['n_out']:>5} pkts  {h['bytes_out']:>10,} bytes  "
                  f"avg {h['avg_size']} B/pkt")
            print(f"  Inbound      : {h['n_in']:>5} pkts  {h['bytes_in']:>10,} bytes")
            print(f"  Ratio        : {h['ratio']}:1")
            print(f"  Timing CV    : "
                  + (f"{h['cv']:.3f}" if h['cv'] is not None else "N/A (too few samples)"))
            print()
            print(f"  Top destinations:")
            for dst, count in list(h["destinations"].items())[:5]:
                flag = " ← external" if not _is_internal(dst) else ""
                print(f"    {dst:<22}  {count:>4} pkts{flag}")
            print()
            print("  Behavioural indicators:")
            for reason in h["reasons"]:
                print(f"    • {reason}")
            print()

    @staticmethod
    def _print_scoring_explanation() -> None:
        print("=" * 72)
        print("SCORING RUBRIC")
        print("=" * 72)
        rows = [
            (f"+{SCORE_SMALL_PACKETS}", f"Avg packet size < {SMALL_PKT_THRESHOLD} B",
             "Keystrokes are small data units; legitimate traffic averages >500 B"),
            (f"+{SCORE_HIGH_RATIO}",    f"Outbound:inbound ratio > {RATIO_THRESHOLD}:1",
             "Keyloggers exfiltrate more than they receive (C&C acks are tiny)"),
            (f"+{SCORE_REGULAR_TIMING}", f"Timing CV < {CV_THRESHOLD}",
             "Periodic scheduled transmission (e.g. every 30 s) → low variance"),
            (f"+{SCORE_SINGLE_DESTINATION}", f"≥{DEST_CONCENTRATION_PCT:.0%} traffic to one IP",
             "Exfiltrated data goes to a single C&C server"),
            (f"+{SCORE_HIGH_FREQUENCY}", f"≥ {FREQ_THRESHOLD} outbound packets",
             "Sustained high-frequency activity over observation window"),
        ]
        for pts, criterion, rationale in rows:
            print(f"  {pts:<4}  {criterion}")
            print(f"        Rationale: {rationale}")
            print()
        print(f"  Hosts scoring ≥ {SUSPICION_THRESHOLD}/{MAX_SCORE} are flagged as suspicious.\n")

    def print_host_detail(self, ip: str) -> None:
        """Print a verbose breakdown for a specific IP."""
        if ip not in self.host_stats:
            print(f"[ERROR] Host {ip} not found in traffic data.")
            return

        hosts = self.detect_suspicious_hosts(threshold=0)
        match = next((h for h in hosts if h["ip"] == ip), None)
        if not match:
            print(f"[INFO] Host {ip} scored 0 — no suspicious criteria met.")
            return

        print(f"\nDETAILED ANALYSIS: {ip}")
        self.print_report([match], explain=True)

    def print_traffic_summary(self) -> None:
        """Print all-hosts traffic table, sorted by total bytes."""
        print("\n" + "=" * 72)
        print("TRAFFIC SUMMARY  (all hosts)")
        print("=" * 72)
        print(f"  {'IP':<18} {'Type':<8} {'Out pkts':>8}  {'In pkts':>8}  "
              f"{'Out bytes':>10}  {'In bytes':>10}  {'Ratio':>6}")
        print("  " + "-" * 68)
        sorted_hosts = sorted(
            self.host_stats.items(),
            key=lambda x: x[1]["bytes_out"] + x[1]["bytes_in"],
            reverse=True,
        )
        for ip, s in sorted_hosts:
            n_out = len(s["outbound_pkts"])
            n_in  = len(s["inbound_pkts"])
            ratio = f"{n_out/max(n_in,1):.1f}" if n_in or n_out else "N/A"
            tag   = "Internal" if _is_internal(ip) else "External"
            print(f"  {ip:<18} {tag:<8} {n_out:>8}  {n_in:>8}  "
                  f"{s['bytes_out']:>10,}  {s['bytes_in']:>10,}  {ratio:>6}")

    # ── Export ─────────────────────────────────────────────────────────────

    def save_json(self, hosts: list, path: str) -> None:
        payload = {
            "generated":    datetime.now().isoformat(),
            "pcap_file":    self.pcap_file,
            "total_packets": len(self.packets),
            "alerts":       hosts,
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=_serialisable)
        print(f"JSON report saved: {path}")

    def save_text(self, hosts: list, path: str) -> None:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.print_report(hosts, explain=True)
            self.print_traffic_summary()
        with open(path, "w") as f:
            f.write(f"KEYLOGGER DETECTION REPORT\nGenerated: {datetime.now()}\n\n")
            f.write(buf.getvalue())
        print(f"Text report saved: {path}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detect keylogger-like behaviour in a PCAP file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python keylogger_detector.py capture.pcap\n"
            "  python keylogger_detector.py capture.pcap --threshold 3\n"
            "  python keylogger_detector.py capture.pcap --explain\n"
            "  python keylogger_detector.py capture.pcap --host 140.82.59.185\n"
            "  python keylogger_detector.py capture.pcap --json -o report.json\n"
        ),
    )
    parser.add_argument("pcap_file",
                        help="Path to PCAP file")
    parser.add_argument("--threshold", type=int, default=SUSPICION_THRESHOLD,
                        help=f"Minimum suspicion score to flag a host "
                             f"(default: {SUSPICION_THRESHOLD}/{MAX_SCORE})")
    parser.add_argument("--explain", action="store_true",
                        help="Print the scoring rubric alongside the report")
    parser.add_argument("--host", metavar="IP",
                        help="Print detailed breakdown for a specific IP")
    parser.add_argument("--summary", action="store_true",
                        help="Print full traffic summary table for all hosts")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save report to file")
    parser.add_argument("--json", action="store_true",
                        help="Save report as JSON")
    args = parser.parse_args()

    detector = KeyloggerDetector(args.pcap_file)

    if not detector.load_pcap():
        sys.exit(1)

    detector.analyze_traffic_patterns()

    if args.host:
        detector.print_host_detail(args.host)
        return

    hosts = detector.detect_suspicious_hosts(threshold=args.threshold)
    detector.print_report(hosts, explain=args.explain)

    if args.summary:
        detector.print_traffic_summary()

    if args.output:
        if args.json:
            detector.save_json(hosts, args.output)
        else:
            detector.save_text(hosts, args.output)
    elif args.json:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        detector.save_json(hosts, f"keylogger_report_{ts}.json")

    sys.exit(1 if hosts else 0)


if __name__ == "__main__":
    main()
