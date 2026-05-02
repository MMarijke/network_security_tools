"""
create_test_pcap.py - Test PCAP Generator
CSM060 Information Security

Generates synthetic PCAP files for testing both detection tools.
Replaces the separate test generators from each sub-project.

Usage:
    python create_test_pcap.py                     # port scan (default)
    python create_test_pcap.py --scenario mitm     # ARP spoofing
    python create_test_pcap.py --scenario all      # both
    python create_test_pcap.py --scenario portscan -o my_scan.pcap
"""

import argparse
import struct
import sys
import os

# ── Shared constants ───────────────────────────────────────────────────────

BASE_TIME  = 1388167151   # 2013-12-27 19:59:11 UTC (matches original captures)
ATTACKER_IP = "192.168.1.100"


# ── Pure-struct helpers (no Scapy required) ────────────────────────────────

def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))

PCAP_HEADER = struct.pack("<IHHIIII", 0xD4C3B2A1, 2, 4, 0, 0, 65535, 1)
ETH_STUB    = b"\x00" * 6 + b"\x01" * 6 + b"\x08\x00"   # dummy Ethernet + IPv4 type

def _pkt_record(raw_ip: bytes, ts_sec: int, ts_usec: int = 0) -> bytes:
    frame = ETH_STUB + raw_ip
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame

def _make_tcp(src_ip, dst_ip, sport, dport, flags, seq=1000, ack=0,
              ts_sec=BASE_TIME, ts_usec=0) -> bytes:
    ip_len = 40
    ip = struct.pack(">BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0, 64, 6, 0,
        _ip_bytes(src_ip), _ip_bytes(dst_ip))
    tcp = struct.pack(">HHIIBBHHH",
        sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    return _pkt_record(ip + tcp, ts_sec, ts_usec)


def _make_arp(op, psrc, hwsrc_int, pdst, hwdst_int,
              ts_sec=BASE_TIME, ts_usec=0) -> bytes:
    """
    Build a raw ARP-over-Ethernet frame using struct only.
    hwsrc_int / hwdst_int are ints representing 6-byte MAC addresses.
    """
    def mac_bytes(n):
        return n.to_bytes(6, "big")

    def ip4(s):
        return bytes(int(x) for x in s.split("."))

    # Ethernet header: dst mac | src mac | ether-type 0x0806
    eth = mac_bytes(hwdst_int) + mac_bytes(hwsrc_int) + b"\x08\x06"

    # ARP payload (28 bytes for Ethernet/IPv4)
    arp = struct.pack(">HHBBH",
        1,    # HTYPE Ethernet
        0x0800,  # PTYPE IPv4
        6,    # HLEN
        4,    # PLEN
        op,   # operation: 1=request 2=reply
    ) + mac_bytes(hwsrc_int) + ip4(psrc) + mac_bytes(hwdst_int) + ip4(pdst)

    frame = eth + arp
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


# ── Scenario: port scan ────────────────────────────────────────────────────

SCAN_TARGETS = {
    "192.168.1.1": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                    443, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443],
    "192.168.1.2": [80, 443, 22, 21, 25],
    "192.168.1.3": [80, 443, 22, 21, 25],
}
SYN = 0x02
RST_ACK = 0x14


def create_port_scan_pcap(output: str = "test_port_scan.pcap") -> str:
    records = []
    t_sec = BASE_TIME
    t_usec = 0
    seq = 1000

    for target, ports in SCAN_TARGETS.items():
        for port in ports:
            records.append(_make_tcp(ATTACKER_IP, target, 12345, port,
                                     SYN, seq=seq,
                                     ts_sec=t_sec, ts_usec=t_usec))
            records.append(_make_tcp(target, ATTACKER_IP, port, 12345,
                                     RST_ACK, seq=0, ack=seq + 1,
                                     ts_sec=t_sec, ts_usec=t_usec + 50_000))
            t_usec += 100_000
            if t_usec >= 1_000_000:
                t_sec  += 1
                t_usec -= 1_000_000
            seq += 1

    with open(output, "wb") as f:
        f.write(PCAP_HEADER)
        for r in records:
            f.write(r)

    n_pkts = len(records)
    print(f"Port scan PCAP  : {output}  ({n_pkts} packets)")
    print(f"  Attacker      : {ATTACKER_IP}")
    print(f"  Targets       : {list(SCAN_TARGETS)}")
    print(f"  Test with     : python port_scan.py \"{output}\"")
    return output


# ── Scenario: ARP spoofing / MITM ─────────────────────────────────────────

# MAC addresses as integers for easy struct packing
MAC_ROUTER   = 0x001122334455   # 00:11:22:33:44:55  — gateway
MAC_VICTIM   = 0xAABBCCDDEEFF   # aa:bb:cc:dd:ee:ff  — victim host
MAC_HOST2    = 0x112233445566   # 11:22:33:44:55:66  — another host
MAC_ATTACKER = 0xDEADBEEFCAFE   # de:ad:be:ef:ca:fe  — attacker

ROUTER_IP  = "192.168.1.1"
VICTIM_IP  = "192.168.1.100"
HOST2_IP   = "192.168.1.200"
TARGET_IP  = "192.168.1.50"   # ARP request destination


def create_mitm_pcap(output: str = "test_mitm_traffic.pcap") -> str:
    records = []
    t = BASE_TIME

    # --- Legitimate ARP replies (5 per legitimate host) ---
    legit = [
        (ROUTER_IP, MAC_ROUTER),
        (VICTIM_IP, MAC_VICTIM),
        (HOST2_IP,  MAC_HOST2),
    ]
    for ip, mac in legit:
        for j in range(5):
            records.append(_make_arp(2, ip, mac, TARGET_IP, 0xFFFFFFFFFFFF,
                                     ts_sec=t, ts_usec=j * 100_000))
        t += 1

    # --- Spoofed ARP replies from attacker ---
    # Attacker claims to be the router (poisons victim's ARP cache)
    for j in range(3):
        records.append(_make_arp(2, ROUTER_IP, MAC_ATTACKER,
                                 VICTIM_IP, MAC_VICTIM,
                                 ts_sec=t, ts_usec=j * 200_000))
    t += 1

    # Attacker claims to be the victim (poisons router's ARP cache)
    for j in range(3):
        records.append(_make_arp(2, VICTIM_IP, MAC_ATTACKER,
                                 ROUTER_IP, MAC_ROUTER,
                                 ts_sec=t, ts_usec=j * 200_000))

    with open(output, "wb") as f:
        f.write(PCAP_HEADER)
        for r in records:
            f.write(r)

    n_pkts = len(records)
    print(f"ARP/MITM PCAP   : {output}  ({n_pkts} packets)")
    print(f"  Attacker MAC  : de:ad:be:ef:ca:fe")
    print(f"  Spoofed IPs   : {ROUTER_IP} and {VICTIM_IP}")
    print(f"  Test with     : python arp_spoofing_detector.py \"{output}\"")
    return output


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic PCAP files for testing network security tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scenarios:\n"
            "  portscan   TCP SYN port scan (default)\n"
            "  mitm       ARP spoofing / MITM attack\n"
            "  all        Generate both\n"
        ),
    )
    parser.add_argument("--scenario", choices=["portscan", "mitm", "all"],
                        default="portscan", help="Which scenario to generate")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output filename (ignored when --scenario all)")
    args = parser.parse_args()

    try:
        if args.scenario in ("portscan", "all"):
            out = args.output if args.scenario == "portscan" and args.output \
                  else "test_port_scan.pcap"
            create_port_scan_pcap(out)

        if args.scenario in ("mitm", "all"):
            out = args.output if args.scenario == "mitm" and args.output \
                  else "test_mitm_traffic.pcap"
            create_mitm_pcap(out)

    except Exception as e:
        sys.exit(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
