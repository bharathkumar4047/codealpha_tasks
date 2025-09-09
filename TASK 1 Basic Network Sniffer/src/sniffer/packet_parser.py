
from typing import Dict, Any, Set
from scapy.all import (
    Packet, IP, IPv6, TCP, UDP, ICMP, ARP,
    DNS, DHCP, BOOTP
)
import struct, socket

APP_PORTS = {
    "http": {80},
    "https": {443},
    "ssh": {22},
    "ftp": {21},
    "dns": {53},
    "dhcp": {67, 68},
}

def _app_protocols_from_ports(sport: int, dport: int) -> Set[str]:
    found = set()
    for app, ports in APP_PORTS.items():
        if sport in ports or dport in ports:
            found.add(app)
    return found

def classify_protocols_scapy(pkt: Packet) -> Set[str]:
    labels: Set[str] = set()
    if pkt.haslayer(ARP):
        labels.add("arp")
        return labels
    if pkt.haslayer(IP):
        if pkt.haslayer(TCP): labels.add("tcp")
        if pkt.haslayer(UDP): labels.add("udp")
        if pkt.haslayer(ICMP): labels.add("icmp")
    if pkt.haslayer(IPv6):
        labels.add("ipv6")
        if pkt.haslayer(TCP): labels.add("tcp")
        if pkt.haslayer(UDP): labels.add("udp")
    if pkt.haslayer(DNS): labels.add("dns")
    if pkt.haslayer(DHCP) or pkt.haslayer(BOOTP): labels.add("dhcp")
    sport = dport = None
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
    if sport is not None and dport is not None:
        labels |= _app_protocols_from_ports(sport, dport)
    return labels

def parse_packet_summary_scapy(pkt: Packet) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "timestamp": getattr(pkt, "time", None),
        "src": None, "dst": None,
        "l3": None, "l4": None,
        "sport": None, "dport": None,
        "length": len(pkt) if pkt is not None else None,
        "apps": [],
    }
    if pkt.haslayer(ARP):
        out["l3"] = "ARP"
        try:
            out["src"] = pkt[ARP].psrc
            out["dst"] = pkt[ARP].pdst
        except Exception:
            pass
        return out
    if pkt.haslayer(IP):
        out["l3"] = "IPv4"
        out["src"] = pkt[IP].src; out["dst"] = pkt[IP].dst
        if pkt.haslayer(TCP):
            out["l4"] = "TCP"; out["sport"] = int(pkt[TCP].sport); out["dport"] = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            out["l4"] = "UDP"; out["sport"] = int(pkt[UDP].sport); out["dport"] = int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            out["l4"] = "ICMP"
    elif pkt.haslayer(IPv6):
        out["l3"] = "IPv6"
        out["src"] = pkt[IPv6].src; out["dst"] = pkt[IPv6].dst
        if pkt.haslayer(TCP):
            out["l4"] = "TCP"; out["sport"] = int(pkt[TCP].sport); out["dport"] = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            out["l4"] = "UDP"; out["sport"] = int(pkt[UDP].sport); out["dport"] = int(pkt[UDP].dport)
    labels = classify_protocols_scapy(pkt)
    out["apps"] = sorted(labels - {"tcp","udp","icmp","arp","ipv6"})
    return out

def parse_ether_type(frame: bytes):
    if len(frame) < 14: return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    return eth_type

def parse_ipv4_header(data: bytes):
    if len(data) < 20: return None
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = data[9]
    src = ".".join(map(str, data[12:16]))
    dst = ".".join(map(str, data[16:20]))
    return ihl, proto, src, dst

def parse_transport_ports(proto: int, data: bytes, offset: int):
    if proto == 6 and len(data) >= offset + 4:
        sport = int.from_bytes(data[offset:offset+2], "big")
        dport = int.from_bytes(data[offset+2:offset+4], "big")
        return "TCP", sport, dport
    if proto == 17 and len(data) >= offset + 4:
        sport = int.from_bytes(data[offset:offset+2], "big")
        dport = int.from_bytes(data[offset+2:offset+4], "big")
        return "UDP", sport, dport
    if proto == 1:
        return "ICMP", None, None
    return None, None, None

def classify_protocols_socket(l3: str, l4: str, sport: int, dport: int) -> set:
    labels = set()
    if l3 == "ARP": labels.add("arp")
    if l3 == "IPv6": labels.add("ipv6")
    if l4 == "TCP": labels.add("tcp")
    if l4 == "UDP": labels.add("udp")
    if l4 == "ICMP": labels.add("icmp")
    if sport is not None and dport is not None:
        port_map = {"http": {80}, "https": {443}, "ssh": {22}, "ftp": {21}, "dns": {53}, "dhcp": {67,68}}
        for app, ports in port_map.items():
            if sport in ports or dport in ports: labels.add(app)
    return labels

def parse_packet_summary_socket(frame: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "l3": None, "l4": None,
        "src": None, "dst": None,
        "sport": None, "dport": None,
        "apps": [],
        "length": len(frame) if frame else 0
    }
    if not frame or len(frame) < 14: return out
    eth_type = parse_ether_type(frame)
    if eth_type == 0x0806:
        out["l3"] = "ARP"; return out
    if eth_type == 0x86DD:
        out["l3"] = "IPv6"; return out
    if eth_type != 0x0800:
        return out
    out["l3"] = "IPv4"
    parsed = parse_ipv4_header(frame[14:])
    if not parsed: return out
    ihl, proto, src, dst = parsed
    out["src"], out["dst"] = src, dst
    l4, sport, dport = parse_transport_ports(proto, frame[14:], ihl)
    out["l4"], out["sport"], out["dport"] = l4, sport, dport
    labels = classify_protocols_socket(out["l3"], out["l4"], sport, dport)
    out["apps"] = sorted(labels - {"tcp","udp","icmp","arp","ipv6"})
    return out
