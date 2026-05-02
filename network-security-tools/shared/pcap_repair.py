"""
pcap_repair.py - PCAP Repair Utility
CSM060 Information Security

Attempts to recover packets from corrupted or malformed PCAP files.
Three strategies are available; the default (auto) tries them in order
and uses the first one that recovers packets.

Usage:
    python pcap_repair.py <corrupted_file.pcap>
    python pcap_repair.py <corrupted_file.pcap> --strategy frames
    python pcap_repair.py <corrupted_file.pcap> --strategy tcp
    python pcap_repair.py <corrupted_file.pcap> --strategy header
"""

import struct
import sys
import os
import argparse


# ── Shared helpers ─────────────────────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII",
    0xD4C3B2A1,  # magic number (little-endian)
    2,           # version major
    4,           # version minor
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # network (DLT_EN10MB — Ethernet)
)

BASE_TIMESTAMP = 1388167151  # 2013-12-27 — matches original capture


def _remove_utf8_artifacts(data):
    """Strip UTF-8 replacement characters (0xEF 0xBF 0xBD) from binary data."""
    replacement = b"\xef\xbf\xbd"
    cleaned = data.replace(replacement, b"")
    removed = (len(data) - len(cleaned)) // 3
    if removed:
        print(f"  Removed {removed} UTF-8 replacement character(s)")
    return cleaned


def _write_pcap(packets, output_path):
    """Write a list of raw frame bytes to a valid PCAP file."""
    with open(output_path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for i, frame in enumerate(packets):
            frame_len = len(frame)
            ts_sec = BASE_TIMESTAMP + (i // 1000)
            ts_usec = (i % 1000) * 1000
            f.write(struct.pack("<IIII", ts_sec, ts_usec, frame_len, frame_len))
            f.write(frame)
    print(f"  Written {len(packets)} packets → {output_path}")
    return output_path


def _output_path(input_path, suffix):
    base, ext = os.path.splitext(input_path)
    return f"{base}_{suffix}{ext}"


# ── Strategy 1: header ─────────────────────────────────────────────────────

def repair_header(data, output_path):
    """
    Replace a corrupt global header by prepending a fresh one and locating
    the first plausible packet record in the existing data.
    Best for files where only the 24-byte global header is damaged.
    """
    print("Strategy: header — scanning for first valid packet record...")

    for i in range(0, min(4096, len(data) - 16), 4):
        try:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", data[i:i+16])
            if (
                1_000_000_000 < ts_sec < 2_000_000_000
                and ts_usec < 1_000_000
                and 0 < incl_len <= 65535
                and 0 < orig_len <= 65535
                and incl_len <= orig_len
            ):
                print(f"  First plausible packet record at offset {i}")
                with open(output_path, "wb") as f:
                    f.write(PCAP_GLOBAL_HEADER)
                    f.write(data[i:])
                print(f"  Written repaired file → {output_path}")
                return output_path
        except struct.error:
            continue

    print("  No valid packet record found — strategy failed.")
    return None


# ── Strategy 2: frames ─────────────────────────────────────────────────────

def repair_frames(data, output_path):
    """
    Walk the raw bytes looking for valid Ethernet + IPv4 frame patterns.
    Best for files where packet boundaries are intact but framing data is corrupt.
    """
    print("Strategy: frames — scanning for Ethernet frame patterns...")
    frames = []
    i = 0

    while i < len(data) - 14:
        try:
            eth_type = struct.unpack(">H", data[i+12:i+14])[0]

            if eth_type == 0x0800 and i + 34 <= len(data):   # IPv4
                ip_byte = data[i + 14]
                version = (ip_byte >> 4) & 0xF
                ihl = ip_byte & 0xF
                if version == 4 and ihl >= 5:
                    ip_len = struct.unpack(">H", data[i+16:i+18])[0]
                    if 20 <= ip_len <= 1500:
                        frame_end = i + 14 + ip_len
                        if frame_end <= len(data) and (frame_end - i) >= 60:
                            frames.append(data[i:frame_end])
                            i = frame_end
                            continue

            elif eth_type == 0x0806 and i + 42 <= len(data): # ARP
                frames.append(data[i:i+42])
                i += 42
                continue

        except (struct.error, IndexError):
            pass
        i += 1

    if not frames:
        print("  No valid frames found — strategy failed.")
        return None

    print(f"  Recovered {len(frames)} Ethernet frames")
    return _write_pcap(frames, output_path)


# ── Strategy 3: tcp ────────────────────────────────────────────────────────

def repair_tcp(data, output_path):
    """
    Scan raw bytes for bare IPv4/TCP headers without assuming Ethernet framing.
    Reconstructs minimal Ethernet wrappers around each recovered IP packet.
    Best for heavily corrupted files or captures without Ethernet headers.
    """
    print("Strategy: tcp — scanning for raw IPv4/TCP packet patterns...")
    ETH_STUB = b"\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x06\x08\x00"
    frames = []
    i = 0

    while i < len(data) - 40:
        try:
            version_ihl = data[i]
            version = (version_ihl >> 4) & 0xF
            ihl = version_ihl & 0xF

            if version == 4 and ihl >= 5 and i + 9 < len(data) and data[i+9] == 6:
                ip_len = struct.unpack(">H", data[i+2:i+4])[0]
                if 40 <= ip_len <= 1500:
                    tcp_offset = i + (ihl * 4)
                    if tcp_offset + 14 <= len(data):
                        frames.append(ETH_STUB + data[i:i+ip_len])
                        i += ip_len
                        if len(frames) >= 10_000:
                            print("  Reached 10,000 packet limit — stopping early")
                            break
                        continue
        except (struct.error, IndexError):
            pass
        i += 1

    if not frames:
        print("  No TCP packets found — strategy failed.")
        return None

    print(f"  Recovered {len(frames)} TCP packets")
    return _write_pcap(frames, output_path)


# ── Orchestration ──────────────────────────────────────────────────────────

STRATEGIES = {
    "header": repair_header,
    "frames": repair_frames,
    "tcp":    repair_tcp,
}


def repair(file_path, strategy="auto"):
    """
    Attempt to repair a corrupted PCAP file.

    Parameters
    ----------
    file_path : str
        Path to the corrupted file.
    strategy : str
        One of 'auto', 'header', 'frames', or 'tcp'.

    Returns
    -------
    str or None
        Path to the repaired file, or None on failure.
    """
    print(f"\n=== PCAP Repair  |  file: {file_path} ===\n")

    with open(file_path, "rb") as f:
        data = f.read()

    print(f"Original size : {len(data):,} bytes")
    data = _remove_utf8_artifacts(data)

    order = list(STRATEGIES.keys()) if strategy == "auto" else [strategy]

    for name in order:
        print()
        out = _output_path(file_path, f"repaired_{name}")
        result = STRATEGIES[name](data, out)
        if result:
            print(f"\n✓ Repair succeeded with strategy '{name}'")
            print(f"  Repaired file : {result}")
            print(f"  Analyse with  : python port_scan.py \"{result}\"")
            return result

    print("\n✗ All strategies failed — file may be unrecoverable.")
    return None


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Attempt to recover packets from a corrupted PCAP file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Strategies:\n"
            "  auto    Try header → frames → tcp in order (default)\n"
            "  header  Replace corrupt global header only\n"
            "  frames  Scan for Ethernet frame patterns\n"
            "  tcp     Scan for raw IPv4/TCP patterns (most aggressive)\n"
        ),
    )
    parser.add_argument("pcap_file", help="Path to corrupted PCAP file")
    parser.add_argument(
        "--strategy",
        choices=["auto", "header", "frames", "tcp"],
        default="auto",
        help="Repair strategy (default: auto)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        sys.exit(f"[ERROR] File not found: {args.pcap_file}")

    repair(args.pcap_file, args.strategy)


if __name__ == "__main__":
    main()
