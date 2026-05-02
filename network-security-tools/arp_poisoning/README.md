# ARP Poisoning Analysis Tool

A Python toolkit for detecting and visualising ARP spoofing / ARP cache poisoning attacks in PCAP captures. Built for CSM060 Information Security at Birkbeck, University of London.

## Project Structure

```
arp_poisoning/
├── network_analysis_tool.py          # ARP detection + traffic + port analysis
├── create_visualizations.py          # Chart generator (live PCAP data)
├── Incident_Report_ARP_Spoofing_Attack.md
├── 003_ARP_Poisoning.pcap            # Primary analysis capture
├── protocol_distribution.png         # Figure 3 (protocol breakdown)
├── mac_conflict_analysis.png         # Figure 2 (MAC binding conflict)
├── attack_timeline.png               # Figure 2 (ARP timeline)
├── network_topology_diagram.png      # Figure 1 (topology during attack)
├── requirements.txt
└── README.md
```

## Requirements

```bash
pip install scapy matplotlib
```

## Usage

### Full analysis

```bash
python network_analysis_tool.py 003_ARP_Poisoning.pcap
```

### Selective analysis

```bash
python network_analysis_tool.py capture.pcap --arp-only
python network_analysis_tool.py capture.pcap --traffic-only
python network_analysis_tool.py capture.pcap --ports-only
```

### Save results

```bash
python network_analysis_tool.py capture.pcap -o report.txt
python network_analysis_tool.py capture.pcap --json -o results.json
```

### Generate charts from any PCAP

```bash
python create_visualizations.py 003_ARP_Poisoning.pcap
python create_visualizations.py capture.pcap --out-dir charts/
```

Charts are generated from **live PCAP data** — IP addresses, MAC addresses, packet counts, and timeline data are all read from the capture file, not hardcoded.

## Example Output

```
ARP SPOOFING ANALYSIS
==============================================================
ARP: 12 total  (2 req, 10 reply)
  ⚠ Unusual reply:request ratio (10:2) — possible ARP flood

  ⚠ CRITICAL — IP: 192.168.1.1 [GATEWAY — full subnet at risk]
    Threat: HIGH  Confidence: 0.333  Conflicting MACs: 2
      50:00:33:33:33:33  6 pkt (75.0%)  first: ...  last: ...
      50:00:11:11:11:11  2 pkt (25.0%)  first: ...  last: ...
```

## Detection Logic

### ARP spoofing

Tracks IP-to-MAC bindings across all ARP replies. Any IP claimed by more than one MAC triggers an alert. Confidence score = `min_frequency / max_frequency`:

| Score | Meaning |
|-------|---------|
| ≥ 0.7 | HIGH — both MACs sending at similar rates (active bidirectional poisoning) |
| 0.3–0.7 | MEDIUM — moderate conflict |
| < 0.3 | LOW — one MAC dominates; may be a legitimate network change |

Gateway IPs (`.1`, `.254`) are flagged as CRITICAL because compromise redirects all subnet traffic.

### Port analysis

Only **destination ports** are counted (service ports). Source/ephemeral ports are excluded — they are high-numbered, random, and counting them alongside service ports inflates the list with noise.

## Security Note

This tool is for legitimate security analysis and academic use only. Only analyse captures you are authorised to inspect.
