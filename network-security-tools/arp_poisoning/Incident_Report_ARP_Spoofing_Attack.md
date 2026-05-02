# Incident Report for Malicious Network Activity

**Analysis Date:** 4th January 2026  
**Analysis Time:** 09:14 GMT  
**Analyst:** [Student Name]  
**Module:** CSM060 Information Security  
**PCAP File:** 003 ARP_Poisoning.pcap  

---

## Table of Contents

1. Executive Summary
2. Summary and Timeline of Events
3. Affected Systems
4. Indicators of Compromise (IoCs)
5. Detection Method
6. Impact Assessment
7. Severity Level
8. Mitigation Actions
9. Recommendations
10. References

---

## List of Tables

- Table 1: PCAP File Summary Statistics
- Table 2: ARP Traffic Analysis
- Table 3: Indicators of Compromise Summary
- Table 4: Impact Assessment Matrix

---

## List of Figures

- Figure 1: Network Topology During Attack
- Figure 2: ARP Spoofing Attack Timeline
- Figure 3: MAC Address Conflict Analysis

---

## Executive Summary

This incident report documents the analysis of a network security breach involving ARP spoofing attacks detected in network traffic captured on 4th January 2026. The analysis was conducted using a custom Python-based network analysis tool that identified malicious ARP cache poisoning activities targeting the network gateway.

**Key Findings:**
- **Attack Type:** ARP Spoofing/ARP Cache Poisoning
- **Target:** Gateway IP address 192.168.1.1
- **Threat Level:** MEDIUM (Confidence Score: 0.75)
- **Affected Systems:** Network gateway and potentially all devices on the 192.168.1.0/24 subnet
- **Attack Vector:** Forged ARP reply packets claiming legitimate gateway IP

**Immediate Actions Required:**
- Implement dynamic ARP inspection on network switches
- Deploy network monitoring for ARP anomalies
- Investigate source of malicious MAC address 50:00:33:33:33:33
- Review network access controls and device authentication

---

## Summary and Timeline of Events

### PCAP File Analysis Summary

| Metric | Value |
|--------|-------|
| **Total Packets** | 2,294 |
| **ARP Packets** | 12 |
| **ARP Requests** | 2 |
| **ARP Replies** | 10 |
| **Analysis Duration** | Network capture investigation |
| **Capture Period** | Single network session |

**Table 1: PCAP File Summary Statistics**

### Timeline of Malicious Activity

The analysis reveals a concentrated ARP spoofing attack targeting the network gateway. The attack pattern shows:

1. **Initial Phase:** Legitimate ARP traffic from gateway MAC 50:00:11:11:11:11
2. **Attack Phase:** Introduction of malicious MAC 50:00:33:33:33:33 claiming gateway IP
3. **Persistence Phase:** Continued spoofed ARP replies maintaining false association

**ARP Traffic Breakdown:**

| Packet Type | Count | Percentage |
|-------------|-------|------------|
| ARP Requests | 2 | 16.7% |
| ARP Replies | 10 | 83.3% |
| **Total ARP** | **12** | **100%** |

**Table 2: ARP Traffic Analysis**

The high ratio of ARP replies to requests (5:1) indicates abnormal network behavior consistent with ARP spoofing attacks, where attackers flood the network with unsolicited ARP replies to poison ARP caches (Stallings, 2017).

---

## Affected Systems

### Primary Target
- **IP Address:** 192.168.1.1
- **System Type:** Network Gateway
- **Attack Method:** ARP cache poisoning through forged ARP replies

### Network Impact Scope
The ARP spoofing attack against the gateway IP (192.168.1.1) potentially affects all devices within the 192.168.1.0/24 subnet. Gateway spoofing is particularly critical as it enables man-in-the-middle attacks by redirecting all internet-bound traffic through the attacker's system (Kurose & Ross, 2021).

### Protocol Analysis
- **Primary Protocol:** ARP (Address Resolution Protocol)
- **Attack Vector:** Layer 2 network protocol manipulation
- **Exploitation Method:** ARP cache poisoning via gratuitous ARP replies

The attack exploits the stateless nature of ARP, where devices accept and cache ARP replies without verifying their authenticity (Tanenbaum & Wetherall, 2011). This fundamental weakness in the ARP protocol design makes networks vulnerable to spoofing attacks.

### Packet Analysis Summary
- **Malicious Packets:** 6 ARP replies from 50:00:33:33:33:33
- **Legitimate Packets:** 2 ARP replies from 50:00:11:11:11:11
- **Attack Success Rate:** 75% (based on packet frequency dominance)

---

## Indicators of Compromise (IoCs)

### Network-Level IoCs

| Indicator Type | Value | Description |
|----------------|-------|-------------|
| **Suspicious MAC** | 50:00:33:33:33:33 | Malicious MAC claiming gateway IP |
| **Legitimate MAC** | 50:00:11:11:11:11 | Original gateway MAC address |
| **Target IP** | 192.168.1.1 | Gateway IP under attack |
| **Attack Pattern** | Multiple MACs for single IP | ARP spoofing signature |

**Table 3: Indicators of Compromise Summary**

### Hardware Analysis
The MAC address pattern 50:00:33:33:33:33 suggests a manually configured or spoofed address, as legitimate network hardware typically uses manufacturer-assigned OUI (Organizationally Unique Identifier) prefixes. The repetitive pattern indicates potential use of network testing tools or malicious software configured with arbitrary MAC addresses.

### Attack Characteristics
- **Conflict Ratio:** 2 MAC addresses claiming same IP
- **Dominance Pattern:** 75% malicious traffic, 25% legitimate
- **Attack Persistence:** Sustained spoofing throughout capture period
- **Gateway Targeting:** Critical infrastructure component targeted

---

## Detection Method

### Tool Functionality
The custom Python network analysis tool successfully detected the ARP spoofing attack through multiple detection mechanisms:

1. **IP-MAC Mapping Analysis:** Tracked associations between IP addresses and MAC addresses across all ARP packets
2. **Conflict Detection:** Identified instances where multiple MAC addresses claimed the same IP address
3. **Confidence Scoring:** Calculated threat probability based on packet frequency dominance
4. **Gateway Detection:** Specifically flagged attacks against gateway IPs (.1 and .254 addresses)

### Detection Algorithm
The tool implements a statistical approach to ARP spoofing detection by:
- Parsing ARP reply packets using Scapy library
- Building IP-to-MAC mapping tables with packet counts
- Calculating confidence scores: `dominant_packets / total_packets`
- Classifying threat levels based on confidence thresholds

### Technical Implementation
```python
# Core detection logic (simplified)
for pkt in arp_packets:
    if pkt[ARP].op == 2:  # ARP replies only
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        ip_mac_mapping[ip][mac] += 1
```

This approach aligns with established ARP spoofing detection methodologies that focus on monitoring ARP reply patterns and identifying anomalous IP-MAC associations (Ramachandran & Sikdar, 2006).

### Detection Accuracy
- **True Positive:** Successfully identified ARP spoofing attack
- **Confidence Level:** 0.75 (Medium threat classification)
- **False Negative Rate:** No additional attack types detected (expected for ARP-focused analysis)

---

## Impact Assessment

### Technical Impact
The ARP spoofing attack poses significant security risks to the network infrastructure:

**Immediate Technical Consequences:**
- **Traffic Interception:** All gateway-bound traffic potentially redirected through attacker
- **Man-in-the-Middle Position:** Attacker can monitor, modify, or block network communications
- **Network Disruption:** Legitimate gateway access compromised for affected devices
- **Data Confidentiality Breach:** Sensitive information potentially exposed during transit

### Business Impact Analysis

| Impact Category | Severity | Description |
|------------------|----------|-------------|
| **Data Confidentiality** | High | Potential interception of sensitive communications |
| **Network Availability** | Medium | Intermittent connectivity issues for affected devices |
| **System Integrity** | Medium | Risk of data manipulation during transit |
| **Compliance Risk** | High | Potential GDPR/data protection violations |

**Table 4: Impact Assessment Matrix**

### Economic Implications
- **Operational Disruption:** Network instability affecting business operations
- **Incident Response Costs:** Resources required for investigation and remediation
- **Compliance Penalties:** Potential regulatory fines for data protection breaches
- **Reputational Damage:** Loss of stakeholder confidence in network security

### Regulatory Considerations
Under GDPR Article 32 (Security of Processing), organizations must implement appropriate technical measures to ensure data security. ARP spoofing attacks that enable data interception constitute a potential personal data breach requiring notification under Article 33 (European Parliament, 2016).

---

## Severity Level

**ASSIGNED SEVERITY: MEDIUM-HIGH**

### Justification Criteria
- **Attack Success Rate:** 75% dominance indicates effective compromise
- **Critical Infrastructure Target:** Gateway spoofing affects entire network segment
- **Attack Sophistication:** Sustained, targeted attack pattern
- **Potential for Escalation:** Foundation for advanced persistent threats

### Risk Factors
- **High Impact Potential:** Gateway compromise enables network-wide surveillance
- **Moderate Detection Difficulty:** ARP attacks often go unnoticed without specialized monitoring
- **Low Remediation Complexity:** Countermeasures available but require implementation

The severity assessment follows the NIST Cybersecurity Framework guidelines for incident classification, considering both likelihood and impact factors (NIST, 2018).

---

## Mitigation Actions

### Immediate Response (0-24 hours)
1. **Network Isolation:** Identify and isolate devices with MAC 50:00:33:33:33:33
2. **ARP Cache Clearing:** Force ARP cache refresh on all network devices
3. **Traffic Monitoring:** Implement enhanced logging for ARP traffic patterns
4. **Incident Documentation:** Preserve evidence and maintain chain of custody

### Short-term Measures (1-7 days)
1. **Dynamic ARP Inspection (DAI):** Configure network switches to validate ARP packets
2. **Static ARP Entries:** Implement static ARP mappings for critical infrastructure
3. **Network Segmentation:** Isolate critical systems from general user networks
4. **Monitoring Enhancement:** Deploy specialized ARP monitoring tools

### Long-term Security Improvements (1-4 weeks)
1. **802.1X Authentication:** Implement port-based network access control
2. **Network Access Control (NAC):** Deploy comprehensive device authentication
3. **Security Awareness Training:** Educate staff on network security threats
4. **Incident Response Plan:** Develop specific procedures for ARP spoofing incidents

### Technical Implementation
```bash
# Example Cisco switch DAI configuration
ip dhcp snooping
ip dhcp snooping vlan 1
ip arp inspection vlan 1
interface range fa0/1-24
ip arp inspection trust
```

---

## Recommendations

### Infrastructure Hardening
1. **Switch Security Features**
   - Enable Dynamic ARP Inspection on all access switches
   - Configure DHCP snooping to prevent rogue DHCP servers
   - Implement port security to limit MAC addresses per port

2. **Network Monitoring**
   - Deploy Security Information and Event Management (SIEM) systems
   - Implement real-time ARP monitoring with automated alerting
   - Establish baseline network behavior patterns for anomaly detection

3. **Access Control Enhancement**
   - Implement 802.1X authentication for device access
   - Deploy Network Access Control (NAC) solutions
   - Establish device certificate-based authentication

### Operational Security
1. **Incident Response Procedures**
   - Develop specific playbooks for ARP spoofing incidents
   - Establish clear escalation procedures and communication channels
   - Implement regular incident response training and tabletop exercises

2. **Security Awareness**
   - Conduct regular security awareness training for IT staff
   - Implement security awareness programs for end users
   - Establish clear reporting procedures for suspicious network behavior

3. **Compliance and Governance**
   - Regular security assessments and penetration testing
   - Implement continuous compliance monitoring
   - Establish clear data protection and privacy policies

### Technology Recommendations
Based on industry best practices (SANS Institute, 2020), organizations should implement layered security controls including:
- Network segmentation and micro-segmentation
- Zero-trust network architecture principles
- Continuous network monitoring and threat detection
- Regular security assessments and vulnerability management

---

## References

European Parliament. (2016). *General Data Protection Regulation (GDPR)*. Regulation (EU) 2016/679. Official Journal of the European Union.

Kurose, J. F., & Ross, K. W. (2021). *Computer Networking: A Top-Down Approach* (8th ed.). Pearson Education.

NIST. (2018). *Framework for Improving Critical Infrastructure Cybersecurity* (Version 1.1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.CSWP.04162018

Ramachandran, V., & Sikdar, S. (2006). Detecting ARP spoofing: An active technique. In *Information Systems Security* (pp. 283-294). Springer.

SANS Institute. (2020). *Network Security Monitoring and Analysis*. SANS Reading Room. https://www.sans.org/reading-room/

Stallings, W. (2017). *Network Security Essentials: Applications and Standards* (6th ed.). Pearson Education.

Tanenbaum, A. S., & Wetherall, D. J. (2011). *Computer Networks* (5th ed.). Prentice Hall.

---

**Word Count: 1,847 words (excluding references, tables, and figures)**
