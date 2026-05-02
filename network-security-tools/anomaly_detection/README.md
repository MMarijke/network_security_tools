# Advanced Malware Anomaly Detection Tool

Unsupervised, behaviour-based network anomaly detector for identifying advanced malware activity — ICEDID loaders, Anubis VNC, and similar multi-stage threats. Built for CSM060 Information Security at Birkbeck, University of London.

Metadata-only analysis: no payload inspection, works on encrypted traffic.

## How it works

The tool builds a behavioural profile for each internal host across four independent dimensions, scores each separately, and sums them into a composite anomaly score. Hosts exceeding the configured threshold are flagged.

### Scoring dimensions

| Dimension | What it measures | Max points |
|-----------|-----------------|------------|
| **Protocol** | Entropy, unusual combinations (TCP+UDP+ICMP), rare protocols | 4.0+ |
| **Port** | Unique destination port diversity, high-port count, entropy | 6.5 |
| **Timing** | Per-destination beaconing (CV of intervals), persistent connections | 4.0 |
| **Volume** | Excessive external IPs, small-packet dominance, outbound asymmetry | 4.5 |

Use `--explain` to print the full rubric alongside the report.

### Why per-destination beaconing

Beaconing is evaluated **per destination IP**, not across all packets from a host. A machine browsing ten websites simultaneously has very low aggregate inter-arrival times — if you evaluate timing globally, the beaconing signal from a C2 check-in is masked by browsing noise. Evaluating per destination isolates the periodic signal.

The previous approach (aggregate timing) had a CV of `0.956` on a mixed host — never flagged. The per-destination approach correctly finds `CV=0.000` on the same beacon traffic.

## Project structure

```
anomaly_detection/
├── malware_anomaly_detector.py     # Main detection tool
├── 007_Malware_ICEDID_AnubisVNC.pcap
├── requirements.txt
└── README.md
```

## Requirements

```bash
pip install scapy
```

No `matplotlib`, `numpy`, or other heavy dependencies.

## Usage

```bash
# Standard analysis (balanced profile, threshold 5.0)
python malware_anomaly_detector.py 007_Malware_ICEDID_AnubisVNC.pcap

# More sensitive — lower threshold, catches more
python malware_anomaly_detector.py capture.pcap --profile sensitive

# Lower false-positive rate
python malware_anomaly_detector.py capture.pcap --profile conservative

# Override threshold directly
python malware_anomaly_detector.py capture.pcap --threshold 4.0

# Print scoring rubric in output
python malware_anomaly_detector.py capture.pcap --explain

# Save text report
python malware_anomaly_detector.py capture.pcap -o report.txt

# Save JSON report
python malware_anomaly_detector.py capture.pcap --json -o report.json
```

## Detection profiles

| Profile | Threshold | Use case |
|---------|-----------|----------|
| `conservative` | 7.0 | Production networks — low false-positive rate |
| `balanced` | 5.0 | General analysis (default) |
| `sensitive` | 3.0 | Research / high-sensitivity investigation |

## Example output

```
========================================================================
ADVANCED MALWARE ANOMALY DETECTION REPORT
========================================================================
Generated     : 2026-01-04 09:14:00
Packets       : 8,712
Hosts profiled: 4
Threshold     : 5.0
Alerts        : 1

SUSPICIOUS HOST #1  —  10.7.3.101
----------------------------------------------------
  Anomaly score : 9.50  [HIGH confidence]
  Breakdown     : protocol=2.0  port=3.0  timing=4.0  volume=0.50
  Traffic       : 3,241 pkts  1,847,293 B  (8 external IPs)

  Anomaly indicators:
    • High protocol entropy (1.72 > 1.5)  [+2.0]
    • High destination port diversity (27 unique ports > 20)  [+3.0]
    • Beaconing detected to 2 destination(s) (94.103.84.245, 13.107.3.128) CV=0.041  [+2.5]
    • Persistent communication (834s > 300s)  [+1.5]
    • Outbound-dominant traffic asymmetry (ratio 3.8:1 > 3.0:1)  [+1.0]

  Beaconing details:
    94.103.84.245          481 pkts  interval 1.91s  CV=0.041
    13.107.3.128            49 pkts  interval 2.24s  CV=0.182
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No suspicious hosts detected |
| 1 | One or more hosts flagged |

## ICEDID / Anubis VNC indicators

This malware combination typically produces:

| Indicator | Detection dimension |
|-----------|-------------------|
| Multi-protocol C2 (TCP + UDP + ICMP) | Protocol — unusual mix |
| High-port diversity for multi-channel comms | Port — unique dst count |
| Regular C2 check-ins | Timing — per-destination beaconing |
| Long-running remote access sessions | Timing — persistent communication |
| Multiple C2 server contacts | Volume — excessive external IPs |
| Small keystroke/command packets | Volume — small-packet dominance |

## Security note

For legitimate security analysis and academic use only. Only analyse captures you are authorised to inspect.
