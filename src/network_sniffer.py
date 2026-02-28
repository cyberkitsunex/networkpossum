import sys
import os
import datetime
import json
import threading
from colorama import init, Fore, Style

# Check if scapy is installed
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Ether, wrpcap, rdpcap, get_if_list
except ImportError:
    print("Error: scapy not found. Install with: pip install scapy")
    sys.exit(1)

# Banner Function
def print_banner():
    init(autoreset=True)
    print(Fore.RED + Style.BRIGHT + "="*70)
    print(Fore.RED + Style.BRIGHT + "        ⚠ NETWORKPOSSUM - Network Sniffer Active ⚠")
    print(Fore.RED + Style.BRIGHT + "="*70)
    print(Fore.GREEN + "[+] Sniffing network traffic...")
    print(Fore.GREEN + "[+] Monitoring packets in real-time...")
    print(Fore.YELLOW + "[!] Use responsibly and ethically.")
    print(Fore.RED + "="*70 + "\n")

# Check if running as admin (npcap may block raw packet capture, admin access all network interfaces)
def check_privileges():
    if os.name == "nt":
        print("Note: For full packet capture functionality, run as Administrator.")

# Data Structures
class PacketNode:
    """Node for linked list storing packet info"""
    def __init__(self, info):
        self.info = info
        self.next = None

class PacketLinkedList:
    """Linked list for storing captured packets"""
    def __init__(self):
        self.head = None

    def add_packet(self, info):
        node = PacketNode(info)
        if not self.head:
            self.head = node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = node

    def traverse(self):
        current = self.head
        while current:
            yield current.info
            current = current.next

class BandwidthMap:
    """Custom HashMap-like class for bandwidth tracking"""
    def __init__(self):
        self.keys = []
        self.values = []

    def add(self, key, value):
        if key in self.keys:
            idx = self.keys.index(key)
            self.values[idx] += value
        else:
            self.keys.append(key)
            self.values.append(value)

    def get(self, key):
        if key in self.keys:
            return self.values[self.keys.index(key)]
        return 0

    def all_items(self):
        return zip(self.keys, self.values)

# Global Variables 
packet_list = PacketLinkedList()
bandwidth_ip = BandwidthMap()
bandwidth_proto = BandwidthMap()
stats = BandwidthMap()  # Total packets per protocol

# Packet Handler 
def handle_packet(pkt, verbose=False):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    info = {"time": ts}

    # Ethernet
    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    # ARP
    if pkt.haslayer(ARP):
        stats.add("ARP", 1)
        arp = pkt[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        info.update({"proto": "ARP", "detail": f"{op} {arp.psrc} → {arp.pdst}"})
        _print_packet(info)
    
    # IP
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        info.update({"src_ip": ip.src, "dst_ip": ip.dst, "ttl": ip.ttl})
        bandwidth_ip.add(ip.src, len(pkt))

        # TCP
        if pkt.haslayer(TCP):
            stats.add("TCP", 1)
            tcp = pkt[TCP]
            payload_len = len(tcp.payload)
            info.update({
                "proto": "TCP",
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "flags": _tcp_flags(tcp.flags),
                "payload_len": payload_len,
                "service": _guess_service(tcp.sport, tcp.dport)
            })
            label = f"TCP [{info['flags']}] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}"
            if info["service"]:
                label += f"  ({info['service']})"
            if payload_len:
                label += f"  {payload_len}B"
            info["detail"] = label

            # Credential exposure (HTTP dummy check)
            if tcp.dport == 80 or tcp.sport == 80:
                payload = bytes(tcp.payload).decode(errors="ignore")
                if "username=" in payload or "password=" in payload:
                    info["warning"] = "⚠ Possible plaintext credentials"
            _print_packet(info, verbose)

        # UDP / DNS
        elif pkt.haslayer(UDP):
            stats.add("UDP", 1)
            udp = pkt[UDP]
            info.update({"proto": "UDP", "src_port": udp.sport, "dst_port": udp.dport})
            if pkt.haslayer(DNS):
                stats.add("DNS", 1)
                dns = pkt[DNS]
                if dns.qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    info.update({"proto": "DNS", "detail": f"QUERY {qname}"})
                elif dns.qr == 1 and pkt.haslayer(DNSRR):
                    qname = pkt[DNSRR].rrname.decode(errors="replace").rstrip(".")
                    rdata = pkt[DNSRR].rdata
                    info.update({"proto": "DNS", "detail": f"REPLY {qname} → {rdata}"})
                else:
                    info["detail"] = "DNS (unknown)"
            else:
                label = f"UDP {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}"
                if info.get("service"):
                    label += f"  ({info['service']})"
                info["detail"] = label
            _print_packet(info, verbose)

        # ICMP
        elif pkt.haslayer(ICMP):
            stats.add("ICMP", 1)
            icmp = pkt[ICMP]
            types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded", 5: "Redirect"}
            info.update({"proto": "ICMP", "detail": f"ICMP {types.get(icmp.type, f'type={icmp.type}')} {ip.src} → {ip.dst}"})
            _print_packet(info, verbose)
        
        else:
            stats.add("OTHER", 1)
            info.update({"proto": f"IP/{ip.proto}", "detail": f"{ip.src} → {ip.dst}"})
            _print_packet(info, verbose)

    # Save to linked list
    packet_list.add_packet(info)
    bandwidth_proto.add(info.get("proto", "OTHER"), len(pkt))

# Helper Functions
def _tcp_flags(flags):
    mapping = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG"}
    return "|".join(v for k,v in mapping.items() if k in str(flags))

def _guess_service(sport, dport):
    services = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",25:"SMTP",110:"POP3",143:"IMAP",53:"DNS"}
    return services.get(dport) or services.get(sport) or ""

COLORS = {"TCP":"\033[94m","UDP":"\033[96m","DNS":"\033[93m","ICMP":"\033[95m","ARP":"\033[92m","OTHER":"\033[90m","RESET":"\033[0m"}

def _print_packet(info, verbose=False):
    color = COLORS.get(info.get("proto","OTHER"), "")
    reset = COLORS["RESET"]
    detail = info.get("detail","")
    print(f"{color}[{info.get('proto',''):<5}]{reset} {info.get('time','')} {detail}")
    if verbose:
        for k,v in info.items():
            if k not in ("proto","detail","time"):
                print(f"   {k}: {v}")
    if "warning" in info:
        print(f"   {info['warning']}")

def print_stats():
    print("\n" + "─"*50)
    print("Packet Summary")
    print("─"*50)
    for proto, count in stats.all_items():
        print(f"{proto:<6}: {count}")
    print("─"*50)
    print("Bandwidth per IP:")
    for ip, bw in bandwidth_ip.all_items():
        print(f"{ip:<15}: {bw} bytes")
    print("Bandwidth per Protocol:")
    for proto, bw in bandwidth_proto.all_items():
        print(f"{proto:<6}: {bw} bytes")
    print("─"*50)

def list_interfaces():
    print("Available Interfaces:")
    for iface in get_if_list():
        print(f"  {iface}")

def sniff_thread(interface=None, count=0, filter=None):
    sniff(iface=interface, count=count, filter=filter, prn=handle_packet, store=False)

# CLI Main Menu
def main():
    check_privileges()
    print_banner()
    while True:
        print("\n=== Network Sniffer Menu ===")
        print("1. Start Live Capture")
        print("2. Show Stats & Bandwidth")
        print("3. List Interfaces")
        print("4. Export Logs to JSON/PCAP")
        print("5. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            iface = input("Interface (or leave blank for all): ").strip() or None
            pkt_count = int(input("Number of packets (0=unlimited): ").strip() or 0)
            bpf_filter = input("BPF Filter (optional): ").strip() or None
            print("\nPress Ctrl+C to stop capturing...\n")
            try:
                sniff_thread(iface, pkt_count, bpf_filter)
            except KeyboardInterrupt:
                print("\nCapture stopped.")
        elif choice == "2":
            print_stats()
        elif choice == "3":
            list_interfaces()
        # traffic.log will contain JSON formatted data, you can also use .txt or .json
        elif choice == "4":
            json_file = input("Enter JSON filename (e.g., logs.json): ").strip()
            pcap_file = input("Enter PCAP filename (e.g., capture.pcap): ").strip()
            # JSON export
            packet_data = list(packet_list.traverse())
            if json_file:
                with open(json_file, "w") as f:
                    json.dump(packet_data, f, indent=2, default=str)
                print(f"Saved JSON log → {json_file}")
            elif not packet_data:
                print ("No packets captured yet. Choose 1 to Live capture.")
            # PCAP export
            if pcap_file:
                wrpcap(pcap_file, packet_list.traverse())
                print(f"Saved PCAP → {pcap_file}")
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()