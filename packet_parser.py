from scapy.layers.inet import IP, TCP, UDP, ICMP

def extract_http_request_line(raw_data):
    try:
        data_str = raw_data.decode('utf-8', errors='ignore')
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
            if data_str.startswith(method):
                return data_str.split('\r\n')[0]  # First line of HTTP request
        return None
    except Exception:
        return None

def parse_packet(packet):
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto

    src_port = None
    dst_port = None
    proto_name = None
    raw_data = b""

    if TCP in packet:
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        proto_name = "TCP"
        raw_data = bytes(tcp_layer.payload)
    elif UDP in packet:
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        proto_name = "UDP"
        raw_data = bytes(udp_layer.payload)
    elif ICMP in packet:
        proto_name = "ICMP"
        raw_data = bytes(packet[ICMP].payload)
    else:
        proto_name = f"Other({protocol})"
        raw_data = bytes(ip_layer.payload)

    # Safe payload preview: ASCII printable max 50 chars, . for non-printables
    payload_preview = ''.join(
        chr(b) if 32 <= b <= 126 else '.' for b in raw_data[:50]
    )

    # Extract HTTP request line if TCP and payload exists
    http_request_line = None
    if proto_name == "TCP" and raw_data:
        http_request_line = extract_http_request_line(raw_data)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name,
        "payload_preview": payload_preview,
        "http_request_line": http_request_line
    }
