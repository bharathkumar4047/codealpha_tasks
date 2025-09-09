
from scapy.all import get_if_list

SUPPORTED_PROTOCOLS = {
    "tcp","udp","icmp","arp","ipv6","igmp",
    "dns","dhcp","http","https","ssh","ftp"
}

def list_interfaces():
    print("[INFO] Interfaces visible to Scapy:")
    try:
        for iface in get_if_list():
            print(f" - {iface}")
    except Exception as e:
        print(f"[WARN] Could not list interfaces: {e}")

def normalize_protocols(proto_csv: str):
    if not proto_csv:
        return set()
    parts = [p.strip().lower() for p in proto_csv.split(",") if p.strip()]
    return {p for p in parts if p in SUPPORTED_PROTOCOLS}

def derive_bpf_from_protocols(proto_set: set) -> str:
    l = set()
    if not proto_set:
        return ""
    if {"http","https","ssh","ftp"} & proto_set:
        l.add("tcp")
    if {"dns","dhcp"} & proto_set:
        l.add("udp")
    if "tcp" in proto_set: l.add("tcp")
    if "udp" in proto_set: l.add("udp")
    if "icmp" in proto_set: l.add("icmp")
    if "arp" in proto_set: l.add("arp")
    if "ipv6" in proto_set: l.add("ip6")
    if "igmp" in proto_set: l.add("igmp")
    return " or ".join(sorted(l)) if l else ""
