# Malware C2 Detection Tool

A Python tool for detecting Command-and-Control (C2) communications in network traffic captures (PCAP files). Built for CSM060 Information Security at Birkbeck, University of London.

## Two complementary detection modes

**Beaconing** — periodic, low-jitter connections to a single destination, characteristic of RATs and implants that check in on a schedule.

**Burst** — high-volume, asymmetric HTTPS flows with persistent connections, characteristic of Dridex and similar banking trojans that use bulk transfer rather than beaconing.

Both modes are metadata-only and work on encrypted traffic.

## Project Structure

```
c2_detection/
├── malware_c2_detector.py   # Main detection tool (unified)
├── dridex_analysis.json     # Analysis output artefact
├── 006_Malware_Dridex.pcap
├── requirements.txt
└── README.md
```

## Requirements

```bash
pip install scapy
```

No `matplotlib` or `numpy` dependency.

## Usage

```bash
# Full analysis (beaconing + burst, default)
python malware_c2_detector.py 006_Malware_Dridex.pcap

# Burst mode only (Dridex-style)
python malware_c2_detector.py capture.pcap --mode burst

# Beaconing mode only
python malware_c2_detector.py capture.pcap --mode beaconing

# Add known-bad domains
python malware_c2_detector.py capture.pcap --known-bad evilsite.tk malware.top

# Tune thresholds
python malware_c2_detector.py capture.pcap --min-connections 3 --max-jitter 0.5

# Save JSON report
python malware_c2_detector.py capture.pcap --json -o report.json
```

## Detection logic

### Beaconing detection

All four conditions must hold for a flow to be flagged:

| Condition | Default | Meaning |
|-----------|---------|---------|
| Connections ≥ N | 5 | Enough samples for statistical analysis |
| Jitter CV ≤ threshold | 0.3 | Low variance → regular schedule |
| Periodicity ≥ threshold | 0.7 | Most intervals in plausible beacon range |
| Out:in byte ratio ≥ threshold | 3.0 | Asymmetric — more sent than received |

Jitter uses **coefficient of variation** (stdev/mean of intervals) — dimensionless and scale-independent, avoiding the dimensional mismatch of comparing seconds² to seconds.

### Burst / HTTPS C2 detection

Each HTTPS flow is scored across four signals:

| Signal | Points |
|--------|--------|
| Very high volume (>100 KB) | +3 |
| High volume (>20 KB) | +2 |
| Many large packets (>10) | +2 |
| Long-duration connection (>200s) | +2 |
| Extreme asymmetry (>10:1) | +2 |
| Other volume/persistence/asymmetry | +1 each |

Flows scoring ≥ 3 are flagged. Configurable via `--min-flow-packets`, `--min-flow-bytes`, `--persist-seconds`.

### DNS analysis

Heuristics are explicit and documented — legitimate Microsoft/CDN/telemetry domains and reverse-DNS PTR records are deliberately excluded:

| Heuristic | What it catches |
|-----------|----------------|
| Known-bad list | `foodsgoodforliver.com`, `105711.com`, any `--known-bad` domains |
| Suspicious TLD | `.tk .ml .ga .cf .top .pw .xyz` |
| Suspicious keyword | `temp login update install payload drop` |
| High digit density | >45% digits in non-PTR domains — DGA indicator |
| Very long label | >20 chars — DGA indicator |
| Excessive subdomains | >5 labels in non-PTR records — DNS tunnelling indicator |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No beaconing or burst C2 detected |
| 1 | One or more C2 flows flagged |

## Security note

This tool is for legitimate security analysis and academic use only. Only analyse captures you are authorised to inspect.
