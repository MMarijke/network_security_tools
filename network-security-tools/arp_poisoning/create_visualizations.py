"""
create_visualizations.py - Network Security Visualisation Tool
CSM060 Information Security

Generates analysis charts from LIVE PCAP data using a pure-struct parser
(no Scapy needed). Charts are driven entirely by what is in the capture —
no hardcoded packet counts or MAC addresses.

Charts produced:
  1. protocol_distribution.png
  2. mac_conflict_analysis.png
  3. attack_timeline.png
  4. network_topology_diagram.png

Usage:
    python create_visualizations.py <pcap_file>
    python create_visualizations.py <pcap_file> --out-dir charts/
"""

import struct, sys, os, argparse
from collections import defaultdict, Counter
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch


# ── Pure-struct PCAP reader ────────────────────────────────────────────────

def _mac(b): return ":".join(f"{x:02x}" for x in b)
def _ip(b):  return ".".join(str(x)     for x in b)

class Pkt:
    __slots__= ("ts","size","eth_type","arp_op","arp_psrc","arp_hwsrc",
                "ip_proto","ip_src","ip_dst","tcp_dport","udp_dport")
    def __init__(self):
        for s in self.__slots__: setattr(self,s,None)

def read_pcap(path):
    pkts=[]
    with open(path,"rb") as f:
        hdr=f.read(24)
        if len(hdr)<24: sys.exit(f"[ERROR] File too small: {path}")
        magic=struct.unpack("<I",hdr[:4])[0]
        e="<" if magic==0xA1B2C3D4 else (">" if magic==0xD4C3B2A1 else None)
        if not e: sys.exit(f"[ERROR] Bad PCAP magic: {hex(magic)}")
        while True:
            rh=f.read(16)
            if not rh or len(rh)<16: break
            ts_sec,ts_usec,incl,_=struct.unpack(e+"IIII",rh)
            fr=f.read(incl)
            p=Pkt(); p.ts=ts_sec+ts_usec/1e6; p.size=incl
            if len(fr)<14: pkts.append(p); continue
            et=struct.unpack(">H",fr[12:14])[0]; p.eth_type=et
            if et==0x0806 and len(fr)>=42:
                arp=fr[14:]
                p.arp_op=struct.unpack(">H",arp[6:8])[0]
                p.arp_hwsrc=_mac(arp[8:14]); p.arp_psrc=_ip(arp[14:18])
            elif et==0x0800 and len(fr)>=34:
                ip=fr[14:]; ihl=(ip[0]&0xF)*4
                p.ip_proto=ip[9]; p.ip_src=_ip(ip[12:16]); p.ip_dst=_ip(ip[16:20])
                if ip[9]==6  and len(ip)>=ihl+4: p.tcp_dport=struct.unpack(">H",ip[ihl+2:ihl+4])[0]
                elif ip[9]==17 and len(ip)>=ihl+4: p.udp_dport=struct.unpack(">H",ip[ihl+2:ihl+4])[0]
            pkts.append(p)
    return pkts

def extract_stats(pkts):
    proto=Counter(); reqs=[]; reps=[]; ip_macs=defaultdict(lambda:defaultdict(int))
    for p in pkts:
        if p.eth_type==0x0806:
            proto["ARP"]+=1
            if p.arp_op==1: reqs.append(p)
            elif p.arp_op==2:
                reps.append(p)
                if p.arp_psrc: ip_macs[p.arp_psrc][p.arp_hwsrc]+=1
        elif p.eth_type==0x0800:
            if p.ip_proto==6:   proto["TCP"]+=1
            elif p.ip_proto==17: proto["UDP"]+=1
            elif p.ip_proto==1:  proto["ICMP"]+=1
            else:               proto["Other IP"]+=1
        else: proto["Other"]+=1
    conflicts={ip:macs for ip,macs in ip_macs.items() if len(macs)>1}
    timeline=sorted([(p.ts,p.arp_hwsrc,p.arp_psrc) for p in reps if p.ts])
    return {"total":len(pkts),"proto":proto,"n_req":len(reqs),"n_rep":len(reps),
            "ip_macs":ip_macs,"conflicts":conflicts,"timeline":timeline}

# Colours
C={"legit":"#4CAF50","attack":"#F44336","neutral":"#90CAF9","warn":"#FFA726","bg":"#F8F8F8"}

def _save(fig,path):
    fig.savefig(path,dpi=150,bbox_inches="tight",facecolor=C["bg"])
    plt.close(fig); print(f"  Saved: {path}")

# ── Chart 1 ────────────────────────────────────────────────────────────────

def chart_protocol(stats,out):
    proto=stats["proto"]
    if not proto: print("  [SKIP] No data."); return
    labels=list(proto.keys()); sizes=list(proto.values()); total=sum(sizes)
    colors=[C["warn"] if l=="ARP" else (C["neutral"] if l in ("TCP","UDP") else "#CE93D8") for l in labels]
    fig,ax=plt.subplots(figsize=(9,6),facecolor=C["bg"])
    wedges,_,_=ax.pie(sizes,labels=labels,colors=colors,autopct="%1.1f%%",startangle=90,
                      wedgeprops={"edgecolor":"white","linewidth":1.5},textprops={"fontsize":11})
    for i,l in enumerate(labels):
        if l=="ARP": wedges[i].set_edgecolor("red"); wedges[i].set_linewidth(3)
    ax.text(-1.7,-1.1,
            f"ARP breakdown:\n  Requests : {stats['n_req']}\n  Replies  : {stats['n_rep']}\n"
            f"  Rep:Req ratio: {stats['n_rep']}:{max(stats['n_req'],1)}",
            fontsize=9,bbox=dict(boxstyle="round",facecolor="wheat",alpha=0.8))
    ax.set_title(f"Protocol Distribution — {total:,} packets",fontsize=13,weight="bold",pad=16)
    _save(fig,out)

# ── Chart 2 ────────────────────────────────────────────────────────────────

def chart_conflicts(stats,out):
    if not stats["conflicts"]: print("  [SKIP] No conflicts."); return
    ip=next(iter(stats["conflicts"])); macs=stats["conflicts"][ip]
    total=sum(macs.values())
    srt=sorted(macs.items(),key=lambda x:-x[1])
    labels=[m for m,_ in srt]; sizes=[c for _,c in srt]
    colors=[C["attack"] if i==0 else C["legit"] for i in range(len(srt))]

    fig,(a1,a2)=plt.subplots(1,2,figsize=(13,5),facecolor=C["bg"]); fig.patch.set_facecolor(C["bg"])
    explode=[0.08]+[0]*(len(labels)-1)
    a1.pie(sizes,labels=labels,colors=colors,explode=explode,autopct="%1.1f%%",startangle=90,
           wedgeprops={"edgecolor":"white","linewidth":1.5},textprops={"fontsize":9})
    a1.set_title(f"MAC Distribution — IP {ip}\nTotal ARP Replies: {total}",fontsize=11,weight="bold")

    short=[m[:17]+"…" if len(m)>17 else m for m in labels]
    bars=a2.bar(short,sizes,color=colors,alpha=0.85,edgecolor="white",linewidth=1.2)
    for bar,val in zip(bars,sizes):
        a2.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.05,
                f"{val}\n({val/total*100:.0f}%)",ha="center",va="bottom",fontsize=10,weight="bold")
    a2.axhline(total*0.6,color=C["warn"],   linestyle="--",alpha=0.7,label="Medium threshold (60%)")
    a2.axhline(total*0.8,color=C["attack"], linestyle="--",alpha=0.7,label="High threshold (80%)")
    a2.set_ylabel("Packet count",fontsize=11); a2.set_title("Count by MAC",fontsize=11,weight="bold")
    a2.legend(fontsize=9); a2.set_facecolor(C["bg"])
    fig.suptitle(f"MAC Conflict Analysis — {ip}",fontsize=13,weight="bold",y=1.02)
    _save(fig,out)

# ── Chart 3 ────────────────────────────────────────────────────────────────

def chart_timeline(stats,out):
    tl=stats["timeline"]
    if not tl: print("  [SKIP] No timeline data."); return
    conf=stats["conflicts"]
    all_macs=Counter(mac for _,mac,_ in tl)
    attacker=None
    if conf:
        fip=next(iter(conf))
        attacker=sorted(conf[fip].items(),key=lambda x:-x[1])[0][0]
    else:
        attacker=all_macs.most_common(1)[0][0] if all_macs else None

    base=tl[0][0]; lx=[]; ly=[]; ax_=[]; ay=[]
    for ts,mac,ip in tl:
        rel=ts-base
        if mac==attacker: ax_.append(rel); ay.append(1)
        else:             lx.append(rel);  ly.append(1)

    fig,ax=plt.subplots(figsize=(12,5),facecolor=C["bg"]); ax.set_facecolor(C["bg"])
    if lx:  ax.stem(lx,ly, linefmt="g-",markerfmt="go",basefmt=" ",label="Legitimate ARP replies")
    if ax_: ax.stem(ax_,ay,linefmt="r-",markerfmt="r^",basefmt=" ",
                    label=f"Malicious ARP replies ({attacker})")
    if ax_:
        xmax=max(ax_+(lx or [0]))
        ax.annotate("First malicious\npacket",xy=(ax_[0],1),
                    xytext=(ax_[0]+xmax*0.05,1.35),
                    arrowprops=dict(arrowstyle="->",color="red"),fontsize=9,color="red")
    ax.set_xlabel("Seconds from capture start",fontsize=11)
    ax.set_ylabel("ARP Reply",fontsize=11); ax.set_yticks([])
    ax.set_title("ARP Reply Timeline — Legitimate vs Malicious",fontsize=13,weight="bold")
    ax.legend(fontsize=10); ax.grid(axis="x",alpha=0.3)
    _save(fig,out)

# ── Chart 4 ────────────────────────────────────────────────────────────────

def chart_topology(stats,out):
    ip_macs=stats["ip_macs"]; conf=stats["conflicts"]
    gw_ip=next((ip for ip in ip_macs if ip.endswith(".1")),"Gateway IP")
    attacker_mac=legit_mac=None
    if conf and gw_ip in conf:
        srt=sorted(conf[gw_ip].items(),key=lambda x:-x[1])
        attacker_mac=srt[0][0]; legit_mac=srt[-1][0] if len(srt)>1 else None
    elif gw_ip in ip_macs:
        legit_mac=next(iter(ip_macs[gw_ip]))

    fig,ax=plt.subplots(figsize=(13,8),facecolor="white")
    ax.set_facecolor("white"); ax.axis("off"); ax.set_xlim(0,12); ax.set_ylim(0,10)

    def box(x,y,w,h,fc,ec,txt,fs=9):
        ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.15",
                                    facecolor=fc,edgecolor=ec,linewidth=2))
        ax.text(x+w/2,y+h/2,txt,ha="center",va="center",fontsize=fs,weight="bold")

    box(0.5,7,2.5,1.2,"#C8E6C9","#388E3C",f"Legitimate Gateway\n{gw_ip}\n{legit_mac or '?'}")
    box(9,  7,2.5,1.2,"#FFCDD2","#C62828",f"Attacker Device\nSpoofing {gw_ip}\n{attacker_mac or '?'}")
    box(4.5,4.5,3,1.2,"#BBDEFB","#1565C0","Network Switch\n(Layer 2)")
    for i,(lbl,x) in enumerate([("Victim A",0.2),("Victim B",3),("Victim C",5.8)]):
        box(x,1.5,2,1,"#FFF9C4","#F57F17",lbl)
    box(0.5,8.5,2,0.8,"#E1F5FE","#0277BD","Internet",fs=10)

    ax.annotate("",xy=(1.75,8.5),xytext=(1.75,8.2),
                arrowprops=dict(arrowstyle="-",color="#1565C0",lw=2))
    ax.plot([1.75,6],[7,5.7],color="#388E3C",lw=2)
    for vx in [1.2,4,6.8]: ax.plot([6,vx],[4.5,2.5],color="#1565C0",lw=1.5)
    ax.annotate("",xy=(6.5,5.7),xytext=(9.5,7.2),
                arrowprops=dict(arrowstyle="->",color=C["attack"],lw=2.5,linestyle="dashed"))
    ax.legend(handles=[mpatches.Patch(color="#388E3C",label="Legitimate connection"),
                        mpatches.Patch(color=C["attack"],label="Malicious ARP replies")],
              loc="lower right",fontsize=10)
    ax.set_title(f"Network Topology During ARP Spoofing\n{len(conf)} conflict(s) detected",
                 fontsize=14,weight="bold",pad=14)
    _save(fig,out)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser=argparse.ArgumentParser(description="Generate PCAP-driven security charts")
    parser.add_argument("pcap_file")
    parser.add_argument("--out-dir",default=".")
    args=parser.parse_args()
    if not os.path.exists(args.pcap_file): sys.exit(f"[ERROR] Not found: {args.pcap_file}")
    os.makedirs(args.out_dir,exist_ok=True)

    print(f"Reading: {args.pcap_file}")
    pkts=read_pcap(args.pcap_file)
    print(f"Parsed {len(pkts):,} packets")
    stats=extract_stats(pkts)
    print(f"Protocols : {dict(stats['proto'])}")
    print(f"Conflicts : {list(stats['conflicts'].keys())}\n")

    d=args.out_dir
    chart_protocol(stats, os.path.join(d,"protocol_distribution.png"))
    chart_conflicts(stats,os.path.join(d,"mac_conflict_analysis.png"))
    chart_timeline(stats, os.path.join(d,"attack_timeline.png"))
    chart_topology(stats, os.path.join(d,"network_topology_diagram.png"))
    print("\nDone.")

if __name__=="__main__":
    main()
