"""
data_exfiltration_detector.py - Data Exfiltration Detection Tool
CSM060 Information Security

Detects potential data exfiltration by tracking per-IP byte volumes and
outbound-to-inbound ratios. Works on encrypted traffic — payload content
is never inspected, only packet sizes and directions.

Usage:
    python data_exfiltration_detector.py <pcap_file>
    python data_exfiltration_detector.py <pcap_file> -t 5000 -r 2.0
    python data_exfiltration_detector.py <pcap_file> --verbose
    python data_exfiltration_detector.py <pcap_file> --json -o report.json
"""

from scapy.all import rdpcap, IP
from collections import defaultdict
from datetime import datetime
import argparse
import ipaddress
import json
import sys
import os


# ── Defaults ───────────────────────────────────────────────────────────────

DEFAULT_BYTE_THRESHOLD  = 10_000   # minimum bytes sent before flagging
DEFAULT_RATIO_THRESHOLD = 3.0      # minimum sent:received ratio

# RFC 1918 private ranges
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Verbose threshold sweep — mirrors what analyze_traffic.py used to do
THRESHOLD_SWEEP = [
    (10_000, 3.0,  "Standard"),
    (5_000,  2.0,  "Sensitive"),
    (1_000,  1.5,  "High sensitivity"),
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


# ── PCAP loading ───────────────────────────────────────────────────────────

def load_pcap(path: str):
    if not os.path.exists(path):
        sys.exit(f"[ERROR] File not found: {path}")
    print(f"Loading: {path}")
    try:
        packets = rdpcap(path)
        print(f"Loaded {len(packets):,} packets")
        return packets
    except Exception as e:
        sys.exit(
            f"[ERROR] Could not read PCAP: {e}\n"
            f"Tip: run  python pcap_repair.py \"{path}\"  to attempt repair."
        )


# ── Traffic statistics ─────────────────────────────────────────────────────

def calculate_stats(packets: list) -> dict:
    """
    Single-pass computation of per-IP byte and packet volumes, plus
    per-conversation (src→dst) byte volumes.

    Byte counts use IP payload length (len(pkt[IP])) rather than the full
    Ethernet frame length so overhead is excluded and volume figures are
    accurate for Layer-3 traffic analysis.

    IPs where received == 0 are retained — a host that only sends and never
    appears as a destination is itself a strong exfiltration signal
    (e.g. DNS tunnelling, one-way data push).
    """
    per_ip: dict = defaultdict(lambda: {
        "sent_bytes": 0, "recv_bytes": 0,
        "sent_pkts":  0, "recv_pkts":  0,
    })
    conversations: dict = defaultdict(int)   # "src→dst" → bytes
    times = []

    for pkt in packets:
        try:
            if not pkt.haslayer(IP):
                continue
            src  = pkt[IP].src
            dst  = pkt[IP].dst
            size = len(pkt[IP])      # IP payload only, excludes Ethernet overhead

            per_ip[src]["sent_bytes"] += size
            per_ip[src]["sent_pkts"]  += 1
            per_ip[dst]["recv_bytes"] += size
            per_ip[dst]["recv_pkts"]  += 1

            conversations[f"{src} → {dst}"] += size

            if hasattr(pkt, "time"):
                times.append(float(pkt.time))

        except Exception as e:
            print(f"[WARN] Packet skipped: {e}")

    return {
        "per_ip":        dict(per_ip),
        "conversations": conversations,
        "start_time":    _ts(min(times)) if times else "N/A",
        "end_time":      _ts(max(times)) if times else "N/A",
        "total_packets": len(packets),
    }


# ── Detection ──────────────────────────────────────────────────────────────

def _risk_level(ip: str, sent: int, received: int, ratio: float) -> str:
    """
    Assign a risk level based on IP type, volume, and ratio.

    Internal hosts are elevated because an internal device sending large
    volumes externally is the primary data exfiltration pattern.
    External hosts with very high outbound ratios may be C2 servers or
    data staging points and are not dismissed.
    """
    internal = _is_internal(ip)

    if internal:
        if ratio >= 5.0 or sent >= 100_000:
            return "HIGH"
        if ratio >= 3.0:
            return "MEDIUM"
        return "LOW"
    else:
        # External hosts: high ratio suggests C2 or staging, not normal server
        if ratio >= 5.0 and sent >= 10_000:
            return "MEDIUM"
        if ratio >= 3.0:
            return "LOW"
        return "INFO"


def detect_exfiltration(
    stats: dict,
    byte_threshold: float = DEFAULT_BYTE_THRESHOLD,
    ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
) -> list:
    """
    Flag IPs whose sent bytes exceed byte_threshold AND whose
    sent:received ratio exceeds ratio_threshold.

    IPs with received == 0 (pure senders) are also flagged when they
    exceed the byte threshold — zero return traffic is itself anomalous.
    """
    alerts = []

    for ip, d in stats["per_ip"].items():
        sent = d["sent_bytes"]
        recv = d["recv_bytes"]

        if sent < byte_threshold:
            continue

        if recv == 0:
            # Pure sender — flag as infinite ratio
            ratio = float("inf")
        else:
            ratio = sent / recv
            if ratio < ratio_threshold:
                continue

        internal = _is_internal(ip)
        s_pkts   = d["sent_pkts"]
        r_pkts   = d["recv_pkts"]

        alerts.append({
            "ip":           ip,
            "internal":     internal,
            "sent_bytes":   sent,
            "recv_bytes":   recv,
            "sent_pkts":    s_pkts,
            "recv_pkts":    r_pkts,
            "ratio":        round(ratio, 2) if ratio != float("inf") else "∞",
            "avg_sent_size": round(sent / s_pkts, 1) if s_pkts else 0,
            "avg_recv_size": round(recv / r_pkts, 1) if r_pkts else 0,
            "risk":         _risk_level(ip, sent, recv,
                                        ratio if ratio != float("inf") else 999),
        })

    # Sort: internal first, then by sent bytes descending
    alerts.sort(key=lambda a: (not a["internal"], -a["sent_bytes"]))
    return alerts


def top_destinations(stats: dict, src_ip: str, n: int = 5) -> list:
    """Return the top-n destinations (by bytes) for a given source IP."""
    prefix = f"{src_ip} → "
    relevant = [
        (convo.split(" → ", 1)[1], size)
        for convo, size in stats["conversations"].items()
        if convo.startswith(prefix)
    ]
    return sorted(relevant, key=lambda x: -x[1])[:n]


# ── Output ─────────────────────────────────────────────────────────────────

def print_report(alerts: list, stats: dict, verbose: bool = False) -> None:
    n_internal = sum(1 for ip in stats["per_ip"] if _is_internal(ip))
    n_external = len(stats["per_ip"]) - n_internal

    print("\n" + "=" * 70)
    print("DATA EXFILTRATION DETECTION REPORT")
    print("=" * 70)
    print(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Capture window   : {stats['start_time']} → {stats['end_time']}")
    print(f"Total packets    : {stats['total_packets']:,}")
    print(f"Unique IPs       : {len(stats['per_ip'])}  "
          f"({n_internal} internal, {n_external} external)")
    print(f"Alerts           : {len(alerts)}\n")

    if not alerts:
        print("✓ No exfiltration patterns detected at current thresholds.")
    else:
        for a in alerts:
            tag = "Internal" if a["internal"] else "External"
            ratio_str = f"{a['ratio']}:1" if a["ratio"] != "∞" else "∞ (no return traffic)"
            print(f"  ⚠ [{a['risk']:<6}]  {a['ip']}  ({tag})")
            print(f"    Sent         : {a['sent_bytes']:>10,} bytes  "
                  f"({a['sent_pkts']} packets,  avg {a['avg_sent_size']} B)")
            print(f"    Received     : {a['recv_bytes']:>10,} bytes  "
                  f"({a['recv_pkts']} packets,  avg {a['avg_recv_size']} B)")
            print(f"    Ratio        : {ratio_str}")

            # Top destinations — key forensic context
            dests = top_destinations(stats, a["ip"])
            if dests:
                print(f"    Top destinations:")
                for dst, size in dests:
                    flag = " ← external" if not _is_internal(dst) else ""
                    print(f"      {dst:<22} {size:>10,} bytes{flag}")
            print()

    # Traffic summary table
    print("=" * 70)
    print("TRAFFIC SUMMARY  (all IPs, sorted by total volume)")
    print("=" * 70)
    print(f"  {'IP':<18} {'Type':<8} {'Sent':>12}  {'Received':>12}  "
          f"{'Ratio':>7}  {'Total':>12}")
    print("  " + "-" * 66)
    sorted_ips = sorted(
        stats["per_ip"].items(),
        key=lambda x: x[1]["sent_bytes"] + x[1]["recv_bytes"],
        reverse=True,
    )
    for ip, d in sorted_ips:
        sent = d["sent_bytes"]; recv = d["recv_bytes"]
        total = sent + recv
        ratio = f"{sent/recv:.2f}" if recv else "∞"
        tag   = "Internal" if _is_internal(ip) else "External"
        print(f"  {ip:<18} {tag:<8} {sent:>12,}  {recv:>12,}  "
              f"{ratio:>7}  {total:>12,}")

    if verbose:
        # Multi-threshold sweep (replaces the old analyze_traffic.py)
        print("\n" + "=" * 70)
        print("THRESHOLD SWEEP")
        print("=" * 70)
        for b_thresh, r_thresh, label in THRESHOLD_SWEEP:
            print(f"\n  [{label}]  ≥{b_thresh:,} bytes  &  ≥{r_thresh}:1 ratio")
            hits = detect_exfiltration(stats, b_thresh, r_thresh)
            if hits:
                for h in hits:
                    print(f"    {h['ip']:<18} sent {h['sent_bytes']:,}  "
                          f"ratio {h['ratio']}:1  [{h['risk']}]")
            else:
                print("    No candidates at this threshold.")


def save_text(alerts: list, stats: dict, path: str) -> None:
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(alerts, stats, verbose=True)
    with open(path, "w") as f:
        f.write(f"DATA EXFILTRATION REPORT\nGenerated: {datetime.now()}\n\n")
        f.write(buf.getvalue())
    print(f"Text report saved: {path}")


def save_json(alerts: list, stats: dict, path: str) -> None:
    # conversations dict has string keys — safe to serialise
    payload = {
        "generated":      datetime.now().isoformat(),
        "capture_start":  stats["start_time"],
        "capture_end":    stats["end_time"],
        "total_packets":  stats["total_packets"],
        "alerts":         alerts,
        "traffic_summary": {
            ip: d for ip, d in sorted(
                stats["per_ip"].items(),
                key=lambda x: -(x[1]["sent_bytes"] + x[1]["recv_bytes"]),
            )
        },
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=_serialisable)
    print(f"JSON report saved: {path}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detect data exfiltration patterns in a PCAP capture.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python data_exfiltration_detector.py capture.pcap\n"
            "  python data_exfiltration_detector.py capture.pcap -t 5000 -r 2.0\n"
            "  python data_exfiltration_detector.py capture.pcap --verbose\n"
            "  python data_exfiltration_detector.py capture.pcap --json -o report.json\n"
        ),
    )
    parser.add_argument("pcap_file",
                        help="Path to PCAP file")
    parser.add_argument("-t", "--threshold", type=float,
                        default=DEFAULT_BYTE_THRESHOLD,
                        help=f"Minimum bytes sent to trigger alert "
                             f"(default: {DEFAULT_BYTE_THRESHOLD:,})")
    parser.add_argument("-r", "--ratio", type=float,
                        default=DEFAULT_RATIO_THRESHOLD,
                        help=f"Minimum sent:received ratio "
                             f"(default: {DEFAULT_RATIO_THRESHOLD})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Include threshold sweep and full conversation table")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save report to file")
    parser.add_argument("--json", action="store_true",
                        help="Save report as JSON (implies --output if -o not set)")
    args = parser.parse_args()

    packets = load_pcap(args.pcap_file)
    stats   = calculate_stats(packets)
    alerts  = detect_exfiltration(stats, args.threshold, args.ratio)

    print_report(alerts, stats, verbose=args.verbose)

    if args.output:
        if args.json:
            save_json(alerts, stats, args.output)
        else:
            save_text(alerts, stats, args.output)
    elif args.json:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_json(alerts, stats, f"exfiltration_report_{ts}.json")

    # Exit code: 0 = clean, 1 = alerts found
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
