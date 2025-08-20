# Basic Python Network Sniffer

---

## Disclaimer

Any actions or activities related to this Network Sniffer are solely your responsibility.  
The misuse of this tool can result in violation of privacy, legal action, or criminal charges depending on your country’s laws.  
**The contributors and creator will not be held responsible for any misuse or damage caused by this tool.**

This sniffer is for **educational and ethical purposes only.**  
Do not use it to capture traffic on networks without explicit permission. Only use it on networks you own or are authorized to monitor.  
If you intend to use it for illegal or unauthorized purposes, please do not use this tool.

---

## Features

- Live packet sniffing on specified network interface
- Parses Ethernet, IP, TCP, UDP, ICMP headers
- Identifies HTTP request lines
- Save captured packets in PCAP format (for Wireshark analysis)
- Command-line interface with multiple filter and output options
- Beginner-friendly, modular Python code

---

## Installation

git clone https://github.com/anand87794/network-sniffer.git

cd network-sniffer

pip install scapy

---

## Usage

Run the script from your terminal.  
**Root/Administrator privileges may be required to capture packets.**

- **Capture 10 packets on `eth0`:**

sudo python3 sniffer.py --iface eth0 --count 10

- **Capture 5 packets and save as PCAP (with verbose output):**

sudo python3 sniffer.py --iface eth0 --count 5 --save capture.pcap --verbose

- **Capture HTTP packets with filter:**

sudo python3 sniffer.py --iface wlan0 --bpf "tcp port 80" --verbose

---

## Notes

- To view available network interfaces, use:

ip a # Linux/macOS
ipconfig # Windows

text

- **PCAP files** can be analyzed in [Wireshark](https://www.wireshark.org/).
- For real network traffic, make sure you are running the script with the proper permissions (`sudo` or administrator).
- For educational/demo use only. Unauthorized sniffing is strictly prohibited.

---

## Troubleshooting

- **Permission Denied:** Run as root/administrator.
- **No packets captured:** Ensure the correct interface is chosen and is up/active.
- **Scapy not found:** Install with `pip install scapy`.

---

**Happy Learning — Use Responsibly!**
