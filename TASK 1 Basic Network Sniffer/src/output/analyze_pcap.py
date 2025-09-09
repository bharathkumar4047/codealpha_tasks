import os
import pyshark

def analyze_pcap(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File not found: {pcap_path}")
        return

    print(f"[INFO] Reading PCAP file: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path)

    packet_count = 0
    protocol_count = {}

    try:
        for packet in cap:
            packet_count += 1
            proto = packet.highest_layer
            protocol_count[proto] = protocol_count.get(proto, 0) + 1
    except Exception as e:
        print(f"[WARNING] Error reading packet: {e}")
    finally:
        cap.close()

    print("\n=== PCAP Analysis Summary ===")
    print(f"Total Packets: {packet_count}")
    print("Protocol Counts:")
    for proto, count in protocol_count.items():
        print(f"  {proto}: {count}")

if __name__ == "__main__":
    file_path = input("Enter the full path of the PCAP file: ").strip().strip('"')
    analyze_pcap(file_path)
