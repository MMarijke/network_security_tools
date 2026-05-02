# Data Exfiltration Detection Tool

A Python tool for detecting potential data exfiltration activity in network traffic captures (PCAP files). Built for CSM060 Information Security at Birkbeck, University of London.

## How it works

Legitimate client traffic is broadly bidirectional. Data exfiltration produces strong **outbound dominance** — an internal host sending significantly more data than it receives. The tool measures this per IP using two configurable signals:

- **Byte threshold** — minimum bytes sent before a host is considered (filters noise)
- **Sent:received ratio** — minimum outbound dominance ratio to trigger an alert

Crucially, the tool also flags **pure senders** (received == 0) as a special case — a host that only transmits and appears nowhere as a destination is itself anomalous, consistent with DNS tunnelling or one-way data push.

Byte counts use **IP payload length only** — Ethernet and lower-layer overhead is excluded so volume figures accurately reflect application data.

## Project Structure

```
data_exfiltration/
├── data_exfiltration_detector.py       # Main detection tool
├── Incident_Report_Data_Exfiltration.md
├── Tool_Output_Summary.md
├── 004_Data_Exfiltration.pcap
├── requirements.txt
└── README.md
```

## Requirements

```bash
pip install scapy
```

## Usage

```bash
# Basic analysis with default thresholds (10,000 bytes, 3:1 ratio)
python data_exfiltration_detector.py capture.pcap

# Lower thresholds for more sensitive detection
python data_exfiltration_detector.py capture.pcap -t 5000 -r 2.0

# Include threshold sweep and full conversation table
python data_exfiltration_detector.py capture.pcap --verbose

# Save text report
python data_exfiltration_detector.py capture.pcap -o report.txt

# Save JSON report
python data_exfiltration_detector.py capture.pcap --json -o report.json
```

## Example Output

```
======================================================================
DATA EXFILTRATION DETECTION REPORT
======================================================================
Generated        : 2026-01-04 08:44:27
Capture window   : 2026-01-04 08:40:00 → 2026-01-04 08:43:15
Total packets    : 426
Unique IPs       : 6  (2 internal, 4 external)
Alerts           : 2

  ⚠ [HIGH  ]  10.1.31.101  (Internal)
    Sent         :    178,392 bytes  (205 packets,  avg 870.2 B)
    Received     :     38,567 bytes  (221 packets,  avg 174.5 B)
    Ratio        : 4.63:1
    Top destinations:
      104.21.80.1            178,392 bytes ← external

  ⚠ [MEDIUM]  104.21.80.1  (External)
    Sent         :     15,891 bytes  (26 packets,  avg 611.2 B)
    Received     :      2,714 bytes  (25 packets,  avg 108.6 B)
    Ratio        : 5.86:1
```

## Risk Levels

| Level | Criteria |
|-------|----------|
| HIGH | Internal IP with ratio ≥ 5:1, or internal IP with > 100 KB sent |
| MEDIUM | Internal IP with ratio ≥ 3:1 — or external IP with ratio ≥ 5:1 and ≥ 10 KB sent |
| LOW | Internal IP above thresholds but lower ratio |
| INFO | External IP flagged at low severity |

External IPs with very high outbound ratios are not dismissed — they may indicate a C2 or data-staging server.

## Threshold Sweep (`--verbose`)

The `--verbose` flag runs three threshold presets and shows all candidates at each level — equivalent to what the old `analyze_traffic.py` script did, now integrated directly:

| Preset | Bytes | Ratio |
|--------|-------|-------|
| Standard | ≥ 10,000 | ≥ 3.0:1 |
| Sensitive | ≥ 5,000 | ≥ 2.0:1 |
| High sensitivity | ≥ 1,000 | ≥ 1.5:1 |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No alerts — clean capture |
| 1 | One or more alerts detected |

Useful for scripting: `python data_exfiltration_detector.py capture.pcap && echo "clean"`.

## Security Note

This tool is for legitimate security analysis and academic use only. Only analyse captures you are authorised to inspect.
