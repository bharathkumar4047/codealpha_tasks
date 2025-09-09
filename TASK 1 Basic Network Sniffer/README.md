
# Basic Network Sniffer — Protocol Filters Edition

Real-time packet capture using Scapy (Windows/macOS/Linux) or raw sockets (Linux).
Adds protocol filtering and detects: tcp, udp, icmp, arp, ipv6, igmp, dns, dhcp, http, https, ssh, ftp.

## Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
List interfaces (Scapy):
```bash
python -m sniffer --list
```

Scapy with protocol filter:
```bash
python -m sniffer --method scapy --iface "Wi-Fi" --protocols "tcp,udp,dns"
```

Socket (Linux) with protocol filter:
```bash
sudo python -m sniffer --method socket --iface any --protocols "tcp,http,https"
```

Provide your own BPF for Scapy (overrides auto-built filter):
```bash
python -m sniffer --method scapy --iface eth0 --bpf "tcp or udp or icmp"
```

Save CSV/PCAP:
```bash
python -m sniffer --method scapy --iface eth0 --protocols "dns" --csv output/dns.csv --pcap output/dns.pcap
```

Notes:
- Scapy recommended on Windows (raw sockets unsupported).
- App-layer filters (`http`, `dns`, etc.) are enforced after capture. BPF auto includes only L3/L4 parts unless you pass `--bpf`.
- Run with elevated privileges.
