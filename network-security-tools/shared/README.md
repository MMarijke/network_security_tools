# Shared Utilities

Tools used across multiple projects in this repository.

## pcap_repair.py

Attempts to recover packets from corrupted or malformed PCAP files.
Three strategies are tried automatically, or you can target one directly.

```bash
python shared/pcap_repair.py corrupted.pcap                    # auto
python shared/pcap_repair.py corrupted.pcap --strategy header  # corrupt header only
python shared/pcap_repair.py corrupted.pcap --strategy frames  # recover Ethernet frames
python shared/pcap_repair.py corrupted.pcap --strategy tcp     # raw IPv4/TCP recovery
```

## create_test_pcap.py

Generates synthetic PCAP files for testing both the port scan and ARP/MITM detectors.
Uses pure Python `struct` — no Scapy required.

```bash
python shared/create_test_pcap.py                      # TCP SYN port scan
python shared/create_test_pcap.py --scenario mitm      # ARP spoofing scenario
python shared/create_test_pcap.py --scenario all       # both
python shared/create_test_pcap.py --scenario mitm -o my_test.pcap
```
