
import socket
from typing import Optional, Set, Callable
from .packet_parser import parse_packet_summary_socket

def sniff_with_socket(interface: Optional[str], proto_set: Set[str],
                      on_row: Callable[[dict], None], count: int = 0):
    captured = 0
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if interface and interface not in ("any", "auto"):
        s.bind((interface, 0))
    while True:
        frame, addr = s.recvfrom(65535)
        row = parse_packet_summary_socket(frame)
        labels = set()
        if row.get("l3") == "ARP": labels.add("arp")
        if row.get("l3") == "IPv6": labels.add("ipv6")
        if row.get("l4") == "TCP": labels.add("tcp")
        if row.get("l4") == "UDP": labels.add("udp")
        if row.get("l4") == "ICMP": labels.add("icmp")
        if row.get("l4") == "IGMP": labels.add("igmp")
        for app in row.get("apps") or []:
            labels.add(app)
        if proto_set and labels.isdisjoint(proto_set):
            continue
        on_row(row)
        captured += 1
        if count and captured >= count:
            break
