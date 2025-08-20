# Basic Python Network Sniffer

## ⚠️ Safety & Ethics

- **Use this tool only on networks you own or have explicit permission to monitor! Sniffing unauthorized traffic is illegal and unethical.**

## Files
- `sniffer.py` – Main CLI and glue logic
- `packet_parser.py` – Parses Ethernet, IP, TCP, UDP, ICMP headers
- `pcap_writer.py` – Save packets to PCAP format
- `utils.py` – Utility functions/helpers

## Install

Python 3 + Scapy:

pip install scapy

sudo python sniffer.py --iface eth0 --count 10
sudo python sniffer.py --iface eth0 --count 5 --save capture.pcap --verbose
sudo python sniffer.py --iface wlan0 --bpf "tcp port 80" --verbose


## CLI Arguments

| Argument   | Description                              |
|------------|------------------------------------------|
| --iface    | Network interface (compulsory)           |
| --count    | Packets to capture (default: unlimited)  |
| --bpf      | BPF filter string (optional)             |
| --save     | PCAP file name for saving (optional)     |
| --verbose  | Detailed output (optional)               |

## Notes

- Linux/Mac: sudo/root required for raw capture
- Windows: Run as administrator  
- PCAP output can be opened in Wireshark  
- Script tested on Linux; should work on Mac/Windows with Scapy

**Happy Sniffing—Legally & Responsibly!**
