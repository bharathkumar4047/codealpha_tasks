
import argparse
import csv
import sys
import time
from datetime import datetime
from typing import Optional, Set
from .utils import list_interfaces, normalize_protocols, derive_bpf_from_protocols
from .sniffer_scapy import sniff_with_scapy
from .sniffer_socket import sniff_with_socket

def print_row(row: dict):
    ts = row.get("timestamp")
    ts_iso = datetime.fromtimestamp(ts).isoformat(timespec="seconds") if isinstance(ts, (int, float)) else datetime.now().isoformat(timespec="seconds")
    src = row.get("src") or "?"
    dst = row.get("dst") or "?"
    l3 = row.get("l3") or "?"
    l4 = row.get("l4") or "?"
    sport = row.get("sport")
    dport = row.get("dport")
    ports = f"{sport}->{dport}" if (sport is not None or dport is not None) else ""
    apps = ",".join(row.get("apps") or [])
    length = row.get("length") or "?"
    print(f"[{ts_iso}] {src} -> {dst}  {l3}/{l4:<4} {ports:<11} len={length} apps={apps}")
    sys.stdout.flush()

def main(argv: Optional[list] = None):
    p = argparse.ArgumentParser(description="Basic Network Sniffer with Protocol Filters")
    p.add_argument("--method", choices=["scapy","socket"], default="scapy", help="Capture backend.")
    p.add_argument("--iface", default="auto", help="Interface name (e.g., eth0, wlan0). 'auto' lets backend decide.")
    p.add_argument("--bpf", default=None, help="BPF filter (Scapy only). Overrides auto-built filter from --protocols.")
    p.add_argument("--protocols", default="", help="Comma list: tcp,udp,icmp,arp,ipv6,igmp,dns,dhcp,http,https,ssh,ftp")
    p.add_argument("--count", type=int, default=0, help="Number of packets to capture (0=infinite).")
    p.add_argument("--csv", default=None, help="Write parsed rows to CSV.")
    p.add_argument("--pcap", default=None, help="Write raw packets to PCAP (Scapy only).")
    p.add_argument("--list", action="store_true", help="List Scapy interfaces and exit.")
    args = p.parse_args(argv)

    if args.list:
        list_interfaces()
        return

    proto_set: Set[str] = normalize_protocols(args.protocols)

    csv_writer = None
    csv_file = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_file, fieldnames=["timestamp","src","dst","l3","l4","sport","dport","length","apps"])
        csv_writer.writeheader()

    def on_row(row: dict):
        print_row(row)
        if csv_writer:
            try:
                csv_writer.writerow({
                    "timestamp": row.get("timestamp") or time.time(),
                    "src": row.get("src"),
                    "dst": row.get("dst"),
                    "l3": row.get("l3"),
                    "l4": row.get("l4"),
                    "sport": row.get("sport"),
                    "dport": row.get("dport"),
                    "length": row.get("length"),
                    "apps": ",".join(row.get("apps") or []),
                })
            except Exception:
                pass

    try:
        if args.method == "scapy":
            auto_bpf = args.bpf or derive_bpf_from_protocols(proto_set)
            sniff_with_scapy(interface=args.iface, bpf_filter=auto_bpf, proto_set=proto_set,
                             on_row=on_row, pcap_path=args.pcap, count=args.count)
        else:
            sniff_with_socket(interface=args.iface, proto_set=proto_set,
                              on_row=on_row, count=args.count)
    except PermissionError:
        print("Permission denied. Run with Administrator/sudo or grant raw capture permissions.", file=sys.stderr)
    finally:
        if csv_file:
            csv_file.close()

if __name__ == "__main__":
    main()
