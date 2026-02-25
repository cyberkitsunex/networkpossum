from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def start_capture(packet_limit=20, iface=None):
    """
    Captures a limited number of packets for analysis.
    Payloads are NOT inspected in Phase 1.
    """

    packets = []

    def handle_packet(packet):
        if IP in packet:
            protocol = "Other"

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"

            packets.append({
                "time": datetime.now().isoformat(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": protocol,
                "length": len(packet)
            })

    sniff(
        iface=iface,
        prn=handle_packet,
        count=packet_limit,
        store=False
    )

    return packets
