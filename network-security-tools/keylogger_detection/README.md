# Keylogger Activity Detection Tool

A Python tool for detecting keylogger-like behaviour in network traffic captures (PCAP files). Built for CSM060 Information Security at Birkbeck, University of London.

## How it works

Keyloggers exhibit distinctive network signatures that are detectable from metadata alone — no payload inspection is required, so detection works on encrypted traffic. The tool scores each host across five behavioural indicators and flags hosts reaching a configurable threshold.

### Scoring rubric

| Points | Criterion | Rationale |
|--------|-----------|-----------|
| +3 | Avg outbound packet size < 100 B | Keystrokes are small; legitimate traffic averages >500 B |
| +2 | Outbound:inbound packet ratio > 3:1 | Keyloggers exfiltrate more than they receive |
| +2 | Timing coefficient of variation < 0.3 | Periodic scheduled transmission → low timing variance |
| +2 | ≥ 70% traffic to a single destination | Exfiltrated data goes to one C&C server |
| +1 | ≥ 50 outbound packets | Sustained continuous activity |

Hosts scoring **≥ 4 / 10** are flagged. Threshold is configurable via `--threshold`.

The timing check uses **coefficient of variation** (stdev / mean of inter-packet intervals) rather than raw variance — this correctly handles different interval scales and avoids the dimensional mismatch of comparing seconds² to seconds.

## Project Structure

```
keylogger_detection/
├── keylogger_detector.py           # Main detection tool
├── METHODOLOGY.md                  # Academic methodology write-up
├── 005_NOOBS_Keylogger.pcap        # Primary analysis capture
├── requirements.txt
└── README.md
```

## Requirements

```bash
pip install scapy
```

## Usage

```bash
# Standard analysis
python keylogger_detector.py capture.pcap

# Lower threshold (flag more hosts)
python keylogger_detector.py capture.pcap --threshold 3

# Print scoring rubric alongside the report
python keylogger_detector.py capture.pcap --explain

# Detailed breakdown for a specific IP
python keylogger_detector.py capture.pcap --host 140.82.59.185

# Full traffic summary table for all hosts
python keylogger_detector.py capture.pcap --summary

# Save text report
python keylogger_detector.py capture.pcap -o report.txt

# Save JSON report
python keylogger_detector.py capture.pcap --json -o report.json
```

## Example output

```
========================================================================
KEYLOGGER ACTIVITY DETECTION REPORT
========================================================================
Generated   : 2026-01-04 09:14:00
PCAP file   : 005_NOOBS_Keylogger.pcap
Packets     : 2,847
Unique IPs  : 8  (3 internal, 5 external)
Alerts      : 1

SUSPICIOUS HOST #1  —  140.82.59.185
----------------------------------------------------
  Score        : 7/10
  Period       : 2026-01-04 09:10:01 → 2026-01-04 09:11:07  (66.0s)

  Outbound     :    42 pkts       2,763 bytes  avg 65.8 B/pkt
  Inbound      :     0 pkts           0 bytes
  Ratio        : 42.0:1
  Timing CV    : 0.142

  Top destinations:
    185.243.115.84          42 pkts ← external

  Behavioural indicators:
    • Small avg packet size (65.8 B < 100 B) — consistent with keystroke-sized payloads  [+3]
    • High outbound:inbound ratio (42.0:1 > 3.0:1) — data exfiltration asymmetry  [+2]
    • Regular transmission timing (CV=0.142 < 0.3) — suggests scheduled/periodic exfiltration  [+2]
    • Concentrated traffic: 100% to 185.243.115.84 — C&C server pattern  [+2]
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No alerts |
| 1 | One or more hosts flagged |

## Limitations

- Requires sufficient packet volume for timing analysis (≥ 3 outbound packets per host)
- Legitimate applications with similar patterns (e.g. IoT telemetry, heartbeat services) may trigger false positives — use `--explain` to review which criteria fired
- Internal ↔ internal traffic is tracked for volume but not scored (no inbound/outbound classification possible without a gateway reference)

## Security note

This tool is for legitimate security analysis and academic use only. Only analyse captures you are authorised to inspect.
