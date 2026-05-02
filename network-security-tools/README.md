# Network Security Analysis Tools

A Python toolkit for analysing network traffic captures (PCAP files) across five attack scenarios. Built for CSM060 Information Security at Birkbeck, University of London.

All tools share a consistent interface: a required `pcap_file` argument, `-o / --output` for saving results, `--json` for structured output, and an exit code of `1` when threats are detected (enabling scripted pipelines).

## Repository Structure

```
network-security-tools/
│
├── port_scan/                      TCP SYN port scan detection
│   ├── port_scan.py
│   ├── Incident_Report.md
│   └── 001_Port_Scan_standard_NPM.pcap
│
├── mitm_detection/                 HTTPS MITM & ARP spoofing detection
│   ├── arp_spoofing_detector.py
│   ├── network_analyzer.py
│   ├── Final_Incident_Report_Network_Security_Analysis.md
│   └── 002_Man-In-The-Middle.pcap
│
├── arp_poisoning/                  ARP cache poisoning analysis + visualisations
│   ├── network_analysis_tool.py
│   ├── create_visualizations.py
│   ├── Incident_Report_ARP_Spoofing_Attack.md
│   ├── 003_ARP_Poisoning.pcap
│   └── *.png                       (4 analysis charts)
│
├── data_exfiltration/              Outbound data exfiltration detection
│   ├── data_exfiltration_detector.py
│   ├── Incident_Report_Data_Exfiltration.md
│   └── 004_Data_Exfiltration.pcap
│
├── keylogger_detection/            Keylogger behavioural pattern detection
│   ├── keylogger_detector.py
│   ├── METHODOLOGY.md
│   └── 005_NOOBS_Keylogger.pcap
│
├── c2_detection/                   Malware C2 / Dridex detection
│   ├── malware_c2_detector.py
│   ├── dridex_analysis.json
│   └── 006_Malware_Dridex.pcap
│
├── anomaly_detection/              Multi-dimension behavioural anomaly detection (ICEDID/VNC)
│   ├── malware_anomaly_detector.py
│   └── 007_Malware_ICEDID_AnubisVNC.pcap
│
├── shared/                         Utilities shared across all projects
│   ├── pcap_repair.py              Repair corrupted PCAP files
│   └── create_test_pcap.py         Generate synthetic test captures
│
├── requirements.txt
├── .gitignore
└── README.md                       This file
```

## Requirements

```bash
pip install -r requirements.txt
```

Core dependency: [Scapy](https://scapy.net/) ≥ 2.5.0. The `create_visualizations.py` script additionally requires `matplotlib`.

## Tools at a glance

### 1 — Port Scan Detection

Detects TCP SYN, NULL, FIN, and XMAS scans with configurable thresholds. Classifies scan type from TCP flag combinations.

```bash
python port_scan/port_scan.py 001_Port_Scan_standard_NPM.pcap
python port_scan/port_scan.py capture.pcap -t 10 --json -o results.json
```

### 2 — MITM & ARP Spoofing Detection

Two tools covering complementary angles of the same attack class.

```bash
# ARP spoofing: tracks IP-to-MAC binding conflicts with confidence scoring
python mitm_detection/arp_spoofing_detector.py 002_Man-In-The-Middle.pcap --verbose

# HTTPS/TLS analysis: flags elevated handshake counts and high-volume port-443 traffic
python mitm_detection/network_analyzer.py 002_Man-In-The-Middle.pcap --json
```

### 3 — ARP Poisoning Analysis + Visualisations

Comprehensive ARP analysis with traffic patterns, port activity, and four live-data charts generated directly from the PCAP.

```bash
python arp_poisoning/network_analysis_tool.py 003_ARP_Poisoning.pcap
python arp_poisoning/create_visualizations.py 003_ARP_Poisoning.pcap --out-dir charts/
```

### 4 — Data Exfiltration Detection

Detects asymmetric outbound traffic patterns. Works on encrypted traffic — only packet sizes and directions are used. Includes threshold sweep and destination tracking.

```bash
python data_exfiltration/data_exfiltration_detector.py 004_Data_Exfiltration.pcap
python data_exfiltration/data_exfiltration_detector.py capture.pcap -t 5000 -r 2.0 --verbose
```

### 5 — Keylogger Detection

Scores hosts across five behavioural indicators (packet size, timing regularity, outbound asymmetry, destination concentration, transmission frequency). Metadata-only — works on encrypted traffic.

```bash
python keylogger_detection/keylogger_detector.py 005_NOOBS_Keylogger.pcap
python keylogger_detection/keylogger_detector.py capture.pcap --explain --host 140.82.59.185
```

### 6 — Malware C2 Detection

Two modes covering different malware communication styles — both metadata-only, both work on encrypted traffic.

```bash
# Full analysis: beaconing + burst/Dridex-style (default)
python c2_detection/malware_c2_detector.py 006_Malware_Dridex.pcap

# Burst mode only (Dridex, banking trojans)
python c2_detection/malware_c2_detector.py capture.pcap --mode burst

# Beaconing mode only (RATs, implants)
python c2_detection/malware_c2_detector.py capture.pcap --mode beaconing

# Add known-bad domains
python c2_detection/malware_c2_detector.py capture.pcap --known-bad evilsite.tk malware.top --json
```

### 7 — Multi-Dimension Behavioural Anomaly Detection

Unsupervised scoring across four independent dimensions — suitable for complex multi-stage threats that don't fit a single detection pattern.

```bash
python anomaly_detection/malware_anomaly_detector.py 007_Malware_ICEDID_AnubisVNC.pcap
python anomaly_detection/malware_anomaly_detector.py capture.pcap --profile sensitive
python anomaly_detection/malware_anomaly_detector.py capture.pcap --explain --json
```

### Shared utilities

```bash
# Repair a corrupted PCAP
python shared/pcap_repair.py corrupted.pcap

# Generate synthetic test captures
python shared/create_test_pcap.py --scenario all
```

## Detection approaches

| Tool | Method | Works on encrypted traffic |
|------|--------|---------------------------|
| Port scan | TCP flag analysis | ✓ (flags visible in headers) |
| ARP spoofing | IP-to-MAC binding conflicts | ✓ (ARP is plaintext) |
| MITM (HTTPS) | TLS handshake count, volume | ✓ |
| Data exfiltration | Byte volume ratios per IP | ✓ |
| Keylogger | Multi-factor behavioural scoring | ✓ |
| C2 beaconing | Timing regularity + asymmetry | ✓ |
| C2 burst (Dridex) | HTTPS volume, persistence, asymmetry | ✓ |
| Anomaly detection | Protocol + port + timing + volume scoring | ✓ |

## Security note

These tools are designed for legitimate network security analysis and academic use. Only analyse network captures you are authorised to inspect.
