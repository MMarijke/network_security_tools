"""
network_analysis_tool.py - Comprehensive Network Analysis Tool
CSM060 Information Security

Full PCAP analysis: ARP spoofing detection + traffic patterns + port activity.
All findings are stored so the summary report reflects real results.

Usage:
    python network_analysis_tool.py <pcap_file>
    python network_analysis_tool.py <pcap_file> --arp-only
    python network_analysis_tool.py <pcap_file> --traffic-only
    python network_analysis_tool.py <pcap_file> --ports-only
    python network_analysis_tool.py <pcap_file> -o report.txt
    python network_analysis_tool.py <pcap_file> --json
"""

from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import json
import sys
import os

WELL_KNOWN_PORTS = {
    20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP-srv",68:"DHCP-cli",80:"HTTP",110:"POP3",123:"NTP",
    143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    8080:"HTTP-alt",8443:"HTTPS-alt",
}
TOP_N = 5

def _ts(epoch):
    try:    return str(datetime.fromtimestamp(float(epoch)))
    except: return "N/A"

def _port_label(p):
    n = WELL_KNOWN_PORTS.get(p,"")
    return f"{p} ({n})" if n else str(p)

def _serial(obj):
    if hasattr(obj,"__str__"): return str(obj)
    raise TypeError

class NetworkAnalyzer:
    def __init__(self, pcap_path):
        self.pcap_path   = pcap_path
        self.packets     = []
        self.arp_pkts    = []
        self.ip_pkts     = []
        self.tcp_pkts    = []
        self.udp_pkts    = []
        self.findings    = {"arp_spoofing":[],"traffic_summary":{},"port_activity":{}}

    def load_pcap(self):
        if not os.path.exists(self.pcap_path):
            sys.exit(f"[ERROR] File not found: {self.pcap_path}")
        print(f"Loading: {self.pcap_path}")
        try:
            self.packets = rdpcap(self.pcap_path)
        except Exception as e:
            sys.exit(f"[ERROR] {e}\nTip: python pcap_repair.py \"{self.pcap_path}\"")
        self.arp_pkts  = [p for p in self.packets if p.haslayer(ARP)]
        self.ip_pkts   = [p for p in self.packets if p.haslayer(IP)]
        self.tcp_pkts  = [p for p in self.packets if p.haslayer(TCP)]
        self.udp_pkts  = [p for p in self.packets if p.haslayer(UDP)]
        print(f"Loaded {len(self.packets):,}  (ARP:{len(self.arp_pkts)} "
              f"IP:{len(self.ip_pkts)} TCP:{len(self.tcp_pkts)} UDP:{len(self.udp_pkts)})")

    def analyze_arp_spoofing(self):
        print("\n"+"="*62+"\nARP SPOOFING ANALYSIS\n"+"="*62)
        if not self.arp_pkts:
            print("No ARP packets found."); return []

        reqs    = [p for p in self.arp_pkts if p[ARP].op==1]
        replies = [p for p in self.arp_pkts if p[ARP].op==2]
        print(f"ARP: {len(self.arp_pkts)} total  ({len(reqs)} req, {len(replies)} reply)")
        if reqs and len(replies)/len(reqs) > 3:
            print(f"  ⚠ Unusual reply:request ratio ({len(replies)}:{len(reqs)}) — possible ARP flood")

        ip_mac    = defaultdict(lambda: defaultdict(int))
        first_ts  = {}; last_ts = {}
        for pkt in replies:
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            k   = (ip, mac)
            ip_mac[ip][mac] += 1
            ts  = float(pkt.time) if hasattr(pkt,"time") else 0.0
            if k not in first_ts: first_ts[k] = ts
            last_ts[k] = ts

        alerts = []
        for ip, macs in sorted(ip_mac.items()):
            if len(macs) < 2: continue
            counts = list(macs.values())
            total  = sum(counts)
            score  = round(min(counts)/max(counts),3) if max(counts) else 0.0
            threat = "HIGH" if score>=0.7 else ("MEDIUM" if score>=0.3 else "LOW")
            is_gw  = ip.endswith(".1") or ip.endswith(".254")
            bindings = [{"mac":m,"count":c,"pct":round(c/total*100,1),
                         "first_seen":_ts(first_ts.get((ip,m),0)),
                         "last_seen":_ts(last_ts.get((ip,m),0))}
                        for m,c in sorted(macs.items(),key=lambda x:-x[1])]
            alert = {"ip":ip,"is_gateway":is_gw,"conflict_macs":len(macs),
                     "total_replies":total,"confidence":score,
                     "threat_level":threat,"bindings":bindings}
            alerts.append(alert)
            print(f"\n  {'⚠ CRITICAL' if is_gw else '⚠ SUSPICIOUS'} — IP: {ip}"
                  + (" [GATEWAY — full subnet at risk]" if is_gw else ""))
            print(f"    Threat: {threat}  Confidence: {score:.3f}  Conflicting MACs: {len(macs)}")
            for b in bindings:
                print(f"      {b['mac']}  {b['count']} pkt ({b['pct']}%)  "
                      f"first:{b['first_seen']}  last:{b['last_seen']}")

        if not alerts: print("  ✓ No ARP spoofing detected.")
        self.findings["arp_spoofing"] = alerts
        return alerts

    def analyze_traffic_patterns(self):
        print("\n"+"="*62+"\nTRAFFIC PATTERN ANALYSIS\n"+"="*62)
        if not self.packets: print("No packets."); return {}

        proto = Counter(); srcs = Counter(); dsts = Counter()
        conv_bytes = defaultdict(int); sizes=[]; times=[]
        for pkt in self.packets:
            try:
                sizes.append(len(pkt))
                if hasattr(pkt,"time"): times.append(float(pkt.time))
                if pkt.haslayer(IP):
                    s,d = pkt[IP].src, pkt[IP].dst
                    srcs[s]+=1; dsts[d]+=1
                    conv_bytes[f"{s} → {d}"] += len(pkt)
                    if   pkt.haslayer(TCP):  proto["TCP"]+=1
                    elif pkt.haslayer(UDP):  proto["UDP"]+=1
                    elif pkt.haslayer(ICMP): proto["ICMP"]+=1
                    else:                    proto["Other IP"]+=1
                elif pkt.haslayer(ARP): proto["ARP"]+=1
                else: proto["Non-IP"]+=1
            except Exception as e: print(f"[WARN] {e}")

        n   = len(self.packets)
        dur = (max(times)-min(times)) if len(times)>=2 else 0.0
        print(f"Window  : {_ts(min(times)) if times else 'N/A'} → {_ts(max(times)) if times else 'N/A'}")
        print(f"Duration: {dur:.2f}s  Rate: {round(n/dur,2) if dur>0 else 0} pkt/s")
        print(f"Packets : {n:,}  Bytes: {sum(sizes):,}  Avg size: {round(sum(sizes)/n,1) if n else 0} B")
        print("\nProtocols:")
        for p,c in proto.most_common(): print(f"  {p:<12} {c:>5}  ({c/n*100:.1f}%)")
        print(f"\nTop {TOP_N} source IPs:")
        for ip,c in srcs.most_common(TOP_N): print(f"  {ip:<18} {c:>5}")
        print(f"\nTop {TOP_N} destination IPs:")
        for ip,c in dsts.most_common(TOP_N): print(f"  {ip:<18} {c:>5}")
        print(f"\nTop {TOP_N} conversations (bytes):")
        for cv,b in sorted(conv_bytes.items(),key=lambda x:-x[1])[:TOP_N]:
            print(f"  {cv}  {b:,} B")

        summary = {"duration_s":round(dur,2),"total_packets":n,"total_bytes":sum(sizes),
                   "avg_size":round(sum(sizes)/n,1) if n else 0,"protocols":dict(proto),
                   "top_src":dict(srcs.most_common(TOP_N)),"top_dst":dict(dsts.most_common(TOP_N))}
        self.findings["traffic_summary"] = summary
        return summary

    def analyze_port_activity(self):
        """Report destination ports only — source/ephemeral ports excluded to remove noise."""
        print("\n"+"="*62+"\nPORT ACTIVITY ANALYSIS\n"+"="*62)
        tcp_dst = Counter(); udp_dst = Counter()
        for pkt in self.tcp_pkts:
            try: tcp_dst[pkt[TCP].dport]+=1
            except: pass
        for pkt in self.udp_pkts:
            try: udp_dst[pkt[UDP].dport]+=1
            except: pass

        pd = {"tcp_dst":{},"udp_dst":{}}
        if tcp_dst:
            print(f"Top {TOP_N} TCP destination ports:")
            for p,c in tcp_dst.most_common(TOP_N):
                print(f"  {_port_label(p):<22} {c:>5}"); pd["tcp_dst"][p]=c
        else: print("No TCP traffic.")
        if udp_dst:
            print(f"\nTop {TOP_N} UDP destination ports:")
            for p,c in udp_dst.most_common(TOP_N):
                print(f"  {_port_label(p):<22} {c:>5}"); pd["udp_dst"][p]=c
        else: print("No UDP traffic.")

        self.findings["port_activity"] = pd
        return pd

    def print_summary(self):
        print("\n"+"="*62+"\nANALYSIS SUMMARY\n"+"="*62)
        print(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"PCAP      : {self.pcap_path}  ({len(self.packets):,} packets)")
        ts = self.findings["traffic_summary"]
        if ts: print(f"Duration  : {ts.get('duration_s')}s")

        alerts = self.findings["arp_spoofing"]
        print(f"\nARP alerts: {len(alerts)}")
        for a in alerts:
            print(f"  [{a['threat_level']:<6}] {a['ip']}"
                  + (" [GATEWAY]" if a["is_gateway"] else "")
                  + f"  confidence {a['confidence']:.3f}  {a['conflict_macs']} conflicting MACs")

        protos = ts.get("protocols",{})
        if protos:
            n = ts.get("total_packets",1)
            print("\nProtocols:")
            for p,c in sorted(protos.items(),key=lambda x:-x[1]):
                print(f"  {p:<12} {c:>5}  ({c/n*100:.1f}%)")

        pd = self.findings["port_activity"]
        if pd.get("tcp_dst"):
            print("\nTop TCP service ports:")
            for p,c in sorted(pd["tcp_dst"].items(),key=lambda x:-x[1])[:5]:
                print(f"  {_port_label(p):<22} {c:>5}")

    def save_text(self, path):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.print_summary()
        with open(path,"w") as f:
            f.write(f"NETWORK ANALYSIS REPORT\nGenerated: {datetime.now()}\n\n")
            f.write(buf.getvalue())
        print(f"Text report saved: {path}")

    def save_json(self, path):
        with open(path,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),
                       "pcap":self.pcap_path,"findings":self.findings},
                      f, indent=2, default=_serial)
        print(f"JSON report saved: {path}")


def main():
    parser = argparse.ArgumentParser(description="Comprehensive PCAP analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python network_analysis_tool.py capture.pcap\n"
               "  python network_analysis_tool.py capture.pcap --arp-only -o report.txt\n"
               "  python network_analysis_tool.py capture.pcap --json")
    parser.add_argument("pcap_file")
    parser.add_argument("--arp-only",     action="store_true")
    parser.add_argument("--traffic-only", action="store_true")
    parser.add_argument("--ports-only",   action="store_true")
    parser.add_argument("-o","--output",  metavar="FILE")
    parser.add_argument("--json",         action="store_true")
    args = parser.parse_args()

    a = NetworkAnalyzer(args.pcap_file)
    a.load_pcap()
    run_all = not (args.arp_only or args.traffic_only or args.ports_only)
    if args.arp_only     or run_all: a.analyze_arp_spoofing()
    if args.traffic_only or run_all: a.analyze_traffic_patterns()
    if args.ports_only   or run_all: a.analyze_port_activity()
    if run_all: a.print_summary()
    if args.output:
        a.save_json(args.output) if args.json else a.save_text(args.output)
    elif args.json:
        a.save_json(f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

if __name__ == "__main__":
    main()
