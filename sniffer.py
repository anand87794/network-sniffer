import argparse
from scapy.all import sniff
from packet_parser import parse_packet
from pcap_writer import PacketPcapSaver
import time

def parse_args():
    parser = argparse.ArgumentParser(
        description="Basic Python Network Sniffer. Only sniff on networks you own or have permission for."
    )
    parser.add_argument('--iface', required=True, help='Network interface to sniff on (e.g., eth0)')
    parser.add_argument('--count', type=int, default=0, help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('--bpf', default='', help='BPF filter string (e.g., "tcp")')
    parser.add_argument('--save', default='', help='Save captured packets to given PCAP file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

packet_counter = 0  # Global counter

if __name__ == "__main__":
    args = parse_args()
    pcap_saver = None

    if args.save:
        pcap_saver = PacketPcapSaver(args.save)
        print(f"[*] Saving packets to: {args.save}")

    def packet_callback(packet):
        global packet_counter
        packet_counter += 1

        parsed = parse_packet(packet)
        if parsed is None:
            print("[*] Non-IP packet received, skipped.")
            return

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        length = len(packet)

        if args.verbose:
            print(f"Packet #{packet_counter} | Time: {timestamp} | Length: {length} bytes")
            print(f"[{parsed['protocol']}] {parsed['src_ip']}:{parsed['src_port']} --> {parsed['dst_ip']}:{parsed['dst_port']}")
            if parsed['http_request_line']:
                print(f"HTTP Request Line: {parsed['http_request_line']}")
            print(f"Payload preview: {parsed['payload_preview']}")
            print("-" * 70)
        else:
            print(f"[{parsed['protocol']}] {parsed['src_ip']}:{parsed['src_port']} --> {parsed['dst_ip']}:{parsed['dst_port']}")

        if pcap_saver:
            pcap_saver.write_packet(packet)

    print("[*] Starting packet capture...")
    sniff(
        iface=args.iface,
        prn=packet_callback,
        count=args.count if args.count > 0 else 0,
        filter=args.bpf if args.bpf else None,
        store=0
    )
    print("[*] Capture finished.")
    if pcap_saver:
        pcap_saver.close()
        print(f"[*] Packets saved to: {args.save}")
