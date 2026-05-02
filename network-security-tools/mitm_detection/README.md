# MITM & ARP Spoofing Detection Tool

A Python toolkit for detecting Man-in-the-Middle (MITM) attacks and ARP spoofing in network traffic captures (PCAP files). Built for CSM060 Information Security coursework at Birkbeck, University of London.

## Features

- **ARP spoofing detection** — tracks IP-to-MAC bindings across ARP replies; flags IPs claimed by more than one MAC with confidence scoring
- **HTTPS / TLS analysis** — identifies high-volume port 443 traffic and elevated TLS handshake counts as MITM candidate indicators
- **Data exfiltration heuristics** — flags large outbound transfers from RFC 1918 addresses, with configurable subnet override
- **JSON output** — structured results for both tools
- **No false certainty** — findings are clearly labelled as candidates requiring manual verification, not confirmed attacks

## Project Structure

```
mitm_detection/
├── arp_spoofing_detector.py      # ARP spoofing / MITM detection
├── network_analyzer.py           # HTTPS traffic and exfiltration analysis
├── create_test_pcap.py           # Synthetic test PCAP generator (both scenarios)
├── Final_Incident_Report_...md   # Incident report for 002 Man-In-The-Middle.pcap
├── detailed_analysis_report.txt  # Raw analysis output artefact
└── README.md
```

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)

```bash
pip install scapy
```

## Usage

### ARP spoofing detection

```bash
python arp_spoofing_detector.py capture.pcap

# With full binding table
python arp_spoofing_detector.py capture.pcap --verbose

# Save as JSON
python arp_spoofing_detector.py capture.pcap --json -o report.json
```

### Network / HTTPS analysis

```bash
python network_analyzer.py capture.pcap

# Save text report
python network_analyzer.py capture.pcap -o report.txt

# Save JSON report
python network_analyzer.py capture.pcap --json -o report.json

# Override internal subnet (default: all RFC 1918 ranges)
python network_analyzer.py capture.pcap --internal 10.99.0.0/16
```

### Generate test PCAPs

```bash
python create_test_pcap.py                        # TCP SYN port scan
python create_test_pcap.py --scenario mitm        # ARP spoofing scenario
python create_test_pcap.py --scenario all         # Both
python create_test_pcap.py --scenario mitm -o my_mitm.pcap
```

## Example Output

### ARP spoofing detector

```
==============================================================
ARP SPOOFING DETECTION REPORT
==============================================================
Generated  : 2026-01-02 20:39:00
Suspicious IPs detected : 2

  ⚠ CONFLICT DETECTED — IP: 192.168.1.1
    Conflicting MACs   : 2
    Confidence score   : 0.600  [MEDIUM (possible attack or network change)]
    Bindings:
      00:11:22:33:44:55  (5 pkt(s)  first: 2013-12-27 19:59:11  last: ...)
      de:ad:be:ef:ca:fe  (3 pkt(s)  first: 2013-12-27 19:59:14  last: ...)
```

### Network analyser

```
==============================================================
SECURITY FINDINGS
==============================================================
⚠  2 finding(s):

  [MEDIUM] High Volume HTTPS Traffic
           High HTTPS volume: 52 packets from 10.99.99.103
           Note: Candidate indicator only — verify via certificate inspection.

  [HIGH]   Potential Data Exfiltration
           Large outbound transfer: 5,334 bytes from 10.99.99.103
           Note: Threshold-based heuristic. Review destination IP reputation.
```

## Detection Logic

### ARP spoofing

ARP spoofing attacks work by sending unsolicited ARP replies that map an attacker-controlled MAC address to a victim IP. The detector maintains a table of `IP → MAC` bindings from every ARP reply seen. Any IP that accumulates more than one MAC triggers an alert.

**Confidence score** = `min_frequency / max_frequency` across competing MACs.
A score near 1.0 means both MACs are sending at similar rates, consistent with active bidirectional poisoning. A low score means one MAC heavily dominates — more consistent with a one-off network change.

### HTTPS / MITM indicators

| Indicator | Threshold | What it means |
|-----------|-----------|---------------|
| High HTTPS volume | > 50 packets from one source | May indicate a proxy or interceptor — or just a large download |
| Elevated TLS handshakes | > 5 per source | May indicate repeated certificate rejection or proxy re-negotiation |

> **Important:** These are heuristic indicators, not confirmations. A normal HTTPS file download or video stream will also trigger the volume threshold. Confirming a MITM attack requires certificate chain inspection (`openssl s_client`, Wireshark certificate viewer).

### Data exfiltration heuristic

Total outbound bytes per source IP are summed across the capture. Sources exceeding 5 KB of outbound traffic to external IPs are flagged. The internal/external boundary defaults to RFC 1918 space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and can be overridden with `--internal`.

## Security Note

This tool is designed for legitimate security analysis and academic use. Only analyse network captures you are authorised to inspect.
