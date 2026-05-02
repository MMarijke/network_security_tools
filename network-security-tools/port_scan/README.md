# PCAP Port Scan Detection Tool

A Python toolkit for analysing network traffic captures (PCAP files) and detecting port scanning activity. Built for CSM060 Information Security coursework at Birkbeck, University of London.

## Features

- **Port scan detection** — identifies TCP SYN, NULL, FIN, and XMAS scans with configurable thresholds
- **Scan type classification** — labels detected scans by technique (half-open, XMAS, NULL, etc.)
- **Traffic summarisation** — protocol distribution, unique IPs, timing, and packet size statistics
- **JSON output** — structured results for integration with other tools or pipelines
- **PCAP repair** — three-strategy recovery tool for corrupted capture files

## Project Structure

```
port_scan/
├── port_scan.py          # Main analysis tool
├── pcap_repair.py        # PCAP repair utility (replaces the old fixer scripts)
├── create_test_pcap.py   # Synthetic test PCAP generator
├── Incident_Report.md    # Sample incident report from analysing the included PCAP
└── README.md
```

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)

```bash
pip install scapy
```

## Usage

### Analyse a capture

```bash
python port_scan.py capture.pcap
```

### Common options

```bash
# Lower the detection threshold (default 20 unique ports)
python port_scan.py capture.pcap -t 10

# Save results as plain text
python port_scan.py capture.pcap -s

# Save results as JSON
python port_scan.py capture.pcap --json -o results.json

# Validate the PCAP format without running analysis
python port_scan.py capture.pcap -c
```

### Repair a corrupted PCAP

```bash
# Auto mode — tries three strategies in sequence
python pcap_repair.py corrupted.pcap

# Target a specific strategy
python pcap_repair.py corrupted.pcap --strategy header   # corrupt global header only
python pcap_repair.py corrupted.pcap --strategy frames   # recover Ethernet frames
python pcap_repair.py corrupted.pcap --strategy tcp      # recover raw IPv4/TCP packets
```

### Generate a test PCAP

```bash
python create_test_pcap.py                        # writes test_port_scan.pcap
python create_test_pcap.py my_scan.pcap           # custom filename
python create_test_pcap.py --mitm                 # also generate an ARP spoofing sample
```

## Example Output

```
Checking PCAP format...
PCAP format: Standard PCAP (little-endian)
PCAP version : 2.4
Format check: Valid PCAP format

Loading: test_port_scan.pcap  (2,400 bytes)
Loaded 60 packets via rdpcap

Analysing traffic...
Detecting port scans...

=== TRAFFIC SUMMARY ===
Total packets      : 60
Time range         : 2013-12-27 19:59:11 → 2013-12-27 20:00:51
Duration           : 0:01:40.450000
Protocols          : {'TCP': 60}
Unique IPs         : 4
IP addresses       : ['192.168.1.1', '192.168.1.100', '192.168.1.2', '192.168.1.3']
Packet sizes       : avg 40.0 B  min 40 B  max 40 B  total 2,400 B

=== PORT SCAN DETECTION ===
Detected 1 port scan(s):

  Scan #1
    Attacker     : 192.168.1.100
    Target       : 192.168.1.1
    Scan type    : TCP SYN (half-open) scan
    Ports ( 20)  : [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    Packets      : 20
    Window       : 2013-12-27 19:59:11 → 2013-12-27 19:59:12.900000
    Duration     : 0:00:01.900000

Analysis complete — 60 packets processed.
```

## Detection Logic

Port scans are identified by tracking TCP probe packets (SYN flag set, ACK flag not set) from each source IP to each destination IP. When the number of unique destination ports from a single source/destination pair exceeds the configured threshold, a scan is flagged.

Response packets (RST/ACK) from the target are excluded from the count, so the threshold accurately reflects the attacker's probe rate rather than total traffic volume.

Supported scan types:

| Flags | Scan Type |
|-------|-----------|
| SYN only | TCP SYN (half-open) scan |
| No flags | NULL scan |
| FIN only | FIN scan |
| FIN + URG + PSH | XMAS scan |

## PCAP Repair Strategies

| Strategy | Best for |
|----------|----------|
| `header` | Corrupt 24-byte global header, packet data intact |
| `frames` | Corrupt framing data, Ethernet structure partially intact |
| `tcp`    | Heavily corrupted files; reconstructs from raw IP/TCP headers |

## Security Note

This tool is designed for legitimate security analysis and academic use. Only analyse network captures you are authorised to inspect.
