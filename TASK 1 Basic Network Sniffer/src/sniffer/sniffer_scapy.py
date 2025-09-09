
from typing import Optional, Set, Callable
from scapy.all import sniff, PcapWriter
from .packet_parser import parse_packet_summary_scapy, classify_protocols_scapy

def sniff_with_scapy(interface: Optional[str], bpf_filter: Optional[str], proto_set: Set[str],
                     on_row: Callable[[dict], None], pcap_path: Optional[str] = None, count: int = 0):
    pcap_writer = None
    if pcap_path:
        pcap_writer = PcapWriter(pcap_path, append=False, sync=True)

    def _handle(pkt):
        labels = classify_protocols_scapy(pkt)
        if proto_set and labels.isdisjoint(proto_set):
            return
        row = parse_packet_summary_scapy(pkt)
        on_row(row)
        if pcap_writer:
            try:
                pcap_writer.write(pkt)
            except Exception:
                pass

    sniff(iface=None if interface in (None, "auto") else interface,
          filter=bpf_filter if bpf_filter else None,
          prn=_handle, store=False,
          count=0 if not count or count <= 0 else count)
