# Network Analysis Tool Output Summary

## Tool Execution Results

### Basic Detection Tool Output
```
Loading PCAP file: 004 Data_Exfiltration.pcap
Loaded 426 packets
======================================================================
DATA EXFILTRATION DETECTION REPORT
======================================================================
Analysis Time: 2026-01-04 08:44:27.132936
Suspicious Hosts Detected: 2

 SUSPICIOUS EXFILTRATION ACTIVITY
   Source IP: 10.1.31.101
   Data Sent: 178392 bytes
   Data Received: 38567 bytes
   Outbound Ratio: 4.63:1

 SUSPICIOUS EXFILTRATION ACTIVITY
   Source IP: 104.21.80.1
   Data Sent: 15891 bytes
   Data Received: 2714 bytes
   Outbound Ratio: 5.86:1
```

### Enhanced Detection Tool Output
```
Loading PCAP file: 004 Data_Exfiltration.pcap
Loaded 426 packets
================================================================================
ENHANCED DATA EXFILTRATION DETECTION REPORT
================================================================================
Analysis Time: 2026-01-04 08:45:20.700498
Suspicious Hosts Detected: 2
Total IP Addresses: 6 (2 internal, 4 external)

================================================================================
 SUSPICIOUS EXFILTRATION ACTIVITY
   Source IP: 10.1.31.101 (Internal)
   Data Sent: 178,392 bytes (205 packets)
   Data Received: 38,567 bytes (221 packets)
   Outbound Ratio: 4.63:1
   Avg Packet Size: 870.2 bytes sent, 174.5 bytes received
   Risk Level: MEDIUM

 SUSPICIOUS EXFILTRATION ACTIVITY
   Source IP: 104.21.80.1 (External)
   Data Sent: 15,891 bytes (26 packets)
   Data Received: 2,714 bytes (25 packets)
   Outbound Ratio: 5.86:1
   Avg Packet Size: 611.2 bytes sent, 108.6 bytes received
   Risk Level: LOW

================================================================================
TRAFFIC SUMMARY (Top 10 by Total Volume)
================================================================================
IP Address       Type     Sent         Received     Ratio    Total
--------------------------------------------------------------------------------
10.1.31.101      Internal 178,392      38,567       4.63     216,959
208.91.198.143   External 6,860        107,199      0.06     114,059
149.154.167.220  External 11,229       65,614       0.17     76,843
104.21.80.1      External 15,891       2,714        5.86     18,605
193.122.6.168    External 3,966        2,548        1.56     6,514       
10.1.31.1        Internal 621          317          1.96     938
```

### Traffic Analysis Tool Output
```
Loading PCAP file: 004 Data_Exfiltration.pcap
Loaded 426 packets
================================================================================
DETAILED TRAFFIC ANALYSIS
================================================================================
IP Address      Sent (bytes) Received (bytes) Ratio    Total
--------------------------------------------------------------------------------
10.1.31.101     178392       38567           4.63     216959
208.91.198.143  6860         107199          0.06     114059
149.154.167.220 11229        65614           0.17     76843
104.21.80.1     15891        2714            5.86     18605
193.122.6.168   3966         2548            1.56     6514
10.1.31.1       621          317             1.96     938

================================================================================
POTENTIAL EXFILTRATION CANDIDATES (Different Thresholds)
================================================================================

Threshold: 10000 bytes, 3:1 ratio
   10.1.31.101: 178392 sent, 38567 received, 4.63:1 ratio
   104.21.80.1: 15891 sent, 2714 received, 5.86:1 ratio

Threshold: 5000 bytes, 2:1 ratio
   10.1.31.101: 178392 sent, 38567 received, 4.63:1 ratio
   104.21.80.1: 15891 sent, 2714 received, 5.86:1 ratio

Threshold: 1000 bytes, 1.5:1 ratio
   10.1.31.101: 178392 sent, 38567 received, 4.63:1 ratio
   193.122.6.168: 3966 sent, 2548 received, 1.56:1 ratio
   104.21.80.1: 15891 sent, 2714 received, 5.86:1 ratio
```

## Key Findings Summary

1. **Primary Threat**: Internal host 10.1.31.101 with 178,392 bytes sent (4.63:1 ratio)
2. **Secondary Threat**: External host 104.21.80.1 with 15,891 bytes sent (5.86:1 ratio)
3. **Total Packets Analyzed**: 426 packets
4. **Network Scope**: 6 IP addresses (2 internal, 4 external)
5. **Detection Method**: Ratio-based analysis with configurable thresholds
6. **Risk Assessment**: Medium severity data exfiltration incident