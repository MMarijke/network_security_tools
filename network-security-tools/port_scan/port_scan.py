"""
port_scan.py - PCAP Port Scan Detection Tool
CSM060 Information Security

Analyses PCAP capture files for port scanning activity.
Supports TCP SYN scan detection and traffic summarisation.

Usage:
    python port_scan.py <pcap_file> [options]
"""

from scapy.all import rdpcap, TCP, IP, UDP, ICMP, PcapReader
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import sys
import os
import struct
import json


# ── Constants ──────────────────────────────────────────────────────────────

PORT_SCAN_THRESHOLD = 20  # unique destination ports required to flag a scan

# TCP flag bitmasks
TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
}

# Known scan types identified by flag combinations
SCAN_TYPES = {
    0x02: "TCP SYN (half-open) scan",
    0x00: "NULL scan",
    0x01: "FIN scan",
    0x29: "XMAS scan",   # FIN + URG + PSH
    0x03: "SYN+FIN scan (malformed)",
}


# ── PCAP Loading ───────────────────────────────────────────────────────────

def check_pcap_format(file_path):
    """Validate the PCAP global header and return (is_valid, message)."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(24)

        if len(header) < 24:
            return False, "File too small to be a valid PCAP"

        magic = struct.unpack("<I", header[:4])[0]

        if magic == 0xa1b2c3d4:
            endian = "big"
            print("PCAP format: Standard PCAP (big-endian)")
        elif magic == 0xd4c3b2a1:
            endian = "little"
            print("PCAP format: Standard PCAP (little-endian)")
        elif magic == 0x0a0d0d0a:
            return False, "PCAP-NG format detected. Convert to legacy PCAP first (tshark -F pcap)."
        else:
            return False, f"Invalid PCAP magic number: {hex(magic)}"

        fmt = "<HHIIII" if endian == "little" else ">HHIIII"
        version_major, version_minor, _, _, snaplen, network = struct.unpack(fmt, header[4:24])

        print(f"PCAP version : {version_major}.{version_minor}")
        print(f"Snapshot len : {snaplen}")
        print(f"Link type    : {network}")

        return True, "Valid PCAP format"

    except Exception as e:
        return False, f"Error checking PCAP format: {e}"


def load_pcap(file_path):
    """Load packets from a PCAP file. Exits on unrecoverable error."""
    if not os.path.exists(file_path):
        sys.exit(f"[ERROR] File not found: {file_path}")

    if not os.access(file_path, os.R_OK):
        sys.exit(f"[ERROR] Permission denied: {file_path}")

    file_size = os.path.getsize(file_path)
    print(f"Loading: {file_path}  ({file_size:,} bytes)")

    if file_size == 0:
        sys.exit("[ERROR] PCAP file is empty.")

    # Try rdpcap first (loads all at once), fall back to streaming PcapReader
    try:
        packets = rdpcap(file_path)
        print(f"Loaded {len(packets):,} packets via rdpcap")
        return packets
    except Exception as e1:
        print(f"[WARN] rdpcap failed ({e1}), trying PcapReader...")

    try:
        packets = []
        with PcapReader(file_path) as reader:
            for pkt in reader:
                packets.append(pkt)
        print(f"Loaded {len(packets):,} packets via PcapReader")
        return packets
    except Exception as e2:
        sys.exit(
            f"[ERROR] Could not read PCAP file.\n"
            f"  rdpcap error   : {e1}\n"
            f"  PcapReader error: {e2}\n\n"
            f"Tip: run  python pcap_repair.py \"{file_path}\"  to attempt repair."
        )


# ── Analysis ───────────────────────────────────────────────────────────────

def summarise_traffic(packets):
    """Return a dict summarising protocols, IPs, timing, and packet sizes."""
    if not packets:
        return {"error": "No packets to analyse"}

    protocols = Counter()
    ip_addresses = set()
    sizes = []
    times = []

    for i, pkt in enumerate(packets):
        try:
            sizes.append(len(pkt))

            if hasattr(pkt, "time"):
                try:
                    times.append(float(pkt.time))
                except (ValueError, TypeError):
                    pass

            if pkt.haslayer(IP):
                ip_addresses.add(pkt[IP].src)
                ip_addresses.add(pkt[IP].dst)

                if pkt.haslayer(TCP):
                    protocols["TCP"] += 1
                elif pkt.haslayer(UDP):
                    protocols["UDP"] += 1
                elif pkt.haslayer(ICMP):
                    protocols["ICMP"] += 1
                else:
                    protocols["Other IP"] += 1
            else:
                protocols["Non-IP"] += 1

        except Exception as e:
            print(f"[WARN] Packet {i} skipped: {e}")
            protocols["Corrupted"] += 1

    if times:
        try:
            start_time = datetime.fromtimestamp(min(times))
            end_time = datetime.fromtimestamp(max(times))
            duration = end_time - start_time
        except (ValueError, OSError):
            start_time = end_time = duration = "Unknown"
    else:
        start_time = end_time = duration = "Unknown"

    avg_size = round(sum(sizes) / len(sizes), 2) if sizes else 0

    return {
        "total_packets": len(packets),
        "start_time": start_time,
        "end_time": end_time,
        "duration": duration,
        "protocols": dict(protocols),
        "unique_ip_addresses": len(ip_addresses),
        "ip_addresses": sorted(ip_addresses),
        "packet_sizes": {
            "average": avg_size,
            "minimum": min(sizes) if sizes else 0,
            "maximum": max(sizes) if sizes else 0,
            "total_bytes": sum(sizes),
        },
    }


def classify_scan_type(flags_observed):
    """
    Return a human-readable scan type label given the set of TCP flag bytes seen
    from a single source. Uses the most commonly observed flag combination.
    """
    if not flags_observed:
        return "Unknown"

    # Pick the most common flag combination (excluding ACK-only responses)
    for flags in flags_observed:
        if flags in SCAN_TYPES:
            return SCAN_TYPES[flags]

    return f"Custom scan (flags: {', '.join(f'0x{f:02x}' for f in flags_observed)})"


def detect_port_scan(packets, threshold=PORT_SCAN_THRESHOLD):
    """
    Detect port scanning activity in a packet list.

    Only SYN packets (or other non-ACK initiator packets) from a source are
    counted toward the port tally — response packets from the target are
    excluded so the threshold reflects the attacker's actual probe count.

    Returns a list of scan dicts, one per (src, dst) pair that exceeded
    the threshold.
    """
    # scans[src][dst] = set of destination ports probed
    scans = defaultdict(lambda: defaultdict(set))
    # flags_seen[src][dst] = set of TCP flag bytes from initiating packets
    flags_seen = defaultdict(lambda: defaultdict(set))
    timestamps = defaultdict(list)
    packet_counts = defaultdict(int)

    for i, pkt in enumerate(packets):
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            flags = int(pkt[TCP].flags)

            # Only count packets where SYN is set but ACK is not —
            # these are the outgoing probe packets, not responses.
            is_probe = (flags & TCP_FLAGS["SYN"]) and not (flags & TCP_FLAGS["ACK"])

            # Also count NULL, FIN, and XMAS scan patterns (no SYN needed)
            is_stealth_probe = flags in (0x00, 0x01, 0x29) and not (flags & TCP_FLAGS["ACK"])

            if is_probe or is_stealth_probe:
                scans[src][dst].add(pkt[TCP].dport)
                flags_seen[src][dst].add(flags)
                packet_counts[(src, dst)] += 1

                if hasattr(pkt, "time"):
                    try:
                        timestamps[(src, dst)].append(float(pkt.time))
                    except (ValueError, TypeError):
                        pass

        except Exception as e:
            print(f"[WARN] Packet {i} skipped during scan detection: {e}")

    detected_scans = []

    for src, destinations in scans.items():
        for dst, ports in destinations.items():
            if len(ports) < threshold:
                continue

            times = timestamps[(src, dst)]
            scan_type = classify_scan_type(flags_seen[src][dst])

            scan_info = {
                "attacker_ip": src,
                "target_ip": dst,
                "scan_type": scan_type,
                "ports_scanned": sorted(ports),
                "port_count": len(ports),
                "packet_count": packet_counts[(src, dst)],
            }

            if times:
                try:
                    start_dt = datetime.fromtimestamp(min(times))
                    end_dt = datetime.fromtimestamp(max(times))
                    scan_info.update({
                        "start_time": start_dt,
                        "end_time": end_dt,
                        "duration": end_dt - start_dt,
                    })
                except (ValueError, OSError):
                    scan_info.update({"start_time": "Unknown", "end_time": "Unknown", "duration": "Unknown"})
            else:
                scan_info.update({"start_time": "N/A", "end_time": "N/A", "duration": "N/A"})

            detected_scans.append(scan_info)

    return detected_scans


# ── Output ─────────────────────────────────────────────────────────────────

def print_summary(summary):
    print("\n=== TRAFFIC SUMMARY ===")
    if "error" in summary:
        print(f"Error: {summary['error']}")
        return

    print(f"Total packets      : {summary['total_packets']:,}")
    print(f"Time range         : {summary['start_time']} → {summary['end_time']}")
    print(f"Duration           : {summary['duration']}")
    print(f"Protocols          : {summary['protocols']}")
    print(f"Unique IPs         : {summary['unique_ip_addresses']}")

    ips = summary["ip_addresses"]
    display = ips[:10]
    suffix = f"  (+{len(ips) - 10} more)" if len(ips) > 10 else ""
    print(f"IP addresses       : {display}{suffix}")

    sz = summary["packet_sizes"]
    print(f"Packet sizes       : avg {sz['average']} B  min {sz['minimum']} B  "
          f"max {sz['maximum']} B  total {sz['total_bytes']:,} B")


def print_scans(scans):
    print("\n=== PORT SCAN DETECTION ===")
    if not scans:
        print("No port scanning activity detected.")
        return

    print(f"Detected {len(scans)} port scan(s):\n")
    for i, scan in enumerate(scans, 1):
        print(f"  Scan #{i}")
        print(f"    Attacker     : {scan['attacker_ip']}")
        print(f"    Target       : {scan['target_ip']}")
        print(f"    Scan type    : {scan['scan_type']}")
        print(f"    Ports ({scan['port_count']:>3}) : {scan['ports_scanned']}")
        print(f"    Packets      : {scan['packet_count']}")
        print(f"    Window       : {scan['start_time']} → {scan['end_time']}")
        print(f"    Duration     : {scan['duration']}")
        print()


def _serialisable(obj):
    """Convert non-JSON-serialisable types for json.dumps."""
    if isinstance(obj, (datetime,)):
        return str(obj)
    if hasattr(obj, "__str__"):
        return str(obj)
    raise TypeError(f"Not serialisable: {type(obj)}")


def save_results(summary, scans, output_file=None, as_json=False):
    """Write analysis results to a file (text or JSON)."""
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if as_json else "txt"
        output_file = f"pcap_analysis_{timestamp}.{ext}"

    try:
        if as_json:
            payload = {"summary": summary, "port_scans": scans}
            with open(output_file, "w") as f:
                json.dump(payload, f, indent=2, default=_serialisable)
        else:
            with open(output_file, "w") as f:
                f.write("=== PCAP ANALYSIS REPORT ===\n")
                f.write(f"Generated: {datetime.now()}\n\n")

                f.write("=== TRAFFIC SUMMARY ===\n")
                if "error" in summary:
                    f.write(f"Error: {summary['error']}\n")
                else:
                    for key, value in summary.items():
                        if key == "ip_addresses" and len(value) > 10:
                            f.write(f"{key}: {len(value)} addresses (first 10): {value[:10]}\n")
                        else:
                            f.write(f"{key}: {value}\n")

                f.write("\n=== PORT SCAN DETECTION ===\n")
                if not scans:
                    f.write("No port scanning activity detected.\n")
                else:
                    f.write(f"Detected {len(scans)} port scan(s):\n\n")
                    for i, scan in enumerate(scans, 1):
                        f.write(f"Scan #{i}:\n")
                        f.write(f"  Attacker IP  : {scan['attacker_ip']}\n")
                        f.write(f"  Target IP    : {scan['target_ip']}\n")
                        f.write(f"  Scan type    : {scan['scan_type']}\n")
                        f.write(f"  Ports ({scan['port_count']:>3}) : {scan['ports_scanned']}\n")
                        f.write(f"  Packets      : {scan['packet_count']}\n")
                        f.write(f"  Window       : {scan['start_time']} → {scan['end_time']}\n")
                        f.write(f"  Duration     : {scan['duration']}\n\n")

        print(f"Results saved to: {output_file}")
        return output_file

    except Exception as e:
        print(f"[ERROR] Could not save results: {e}")
        return None


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PCAP Port Scan Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python port_scan.py capture.pcap\n"
            "  python port_scan.py capture.pcap -t 10 -s\n"
            "  python port_scan.py capture.pcap --json -o results.json\n"
            "  python port_scan.py capture.pcap -c\n"
        ),
    )
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("-t", "--threshold", type=int, default=PORT_SCAN_THRESHOLD,
                        help=f"Unique-port threshold for scan detection (default: {PORT_SCAN_THRESHOLD})")
    parser.add_argument("-o", "--output", type=str,
                        help="Output file path (default: auto-generated)")
    parser.add_argument("-s", "--save", action="store_true",
                        help="Save results to file")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (implies --save)")
    parser.add_argument("-c", "--check", action="store_true",
                        help="Validate PCAP format and exit")

    args = parser.parse_args()

    print("Checking PCAP format...")
    is_valid, message = check_pcap_format(args.pcap_file)
    print(f"Format check: {message}\n")

    if not is_valid:
        sys.exit(
            "[ERROR] Invalid or corrupted PCAP.\n"
            f"Tip: run  python pcap_repair.py \"{args.pcap_file}\"  to attempt repair."
        )

    if args.check:
        return

    packets = load_pcap(args.pcap_file)

    print("\nAnalysing traffic...")
    summary = summarise_traffic(packets)

    print("Detecting port scans...")
    scans = detect_port_scan(packets, args.threshold)

    print_summary(summary)
    print_scans(scans)

    if args.save or args.json:
        save_results(summary, scans, args.output, as_json=args.json)

    print(f"\nAnalysis complete — {len(packets):,} packets processed.")


if __name__ == "__main__":
    main()
