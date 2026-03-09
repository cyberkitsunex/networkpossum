import sys
import os
import datetime
import json
import urllib.parse
from colorama import init, Fore, Style

try:
    from scapy.all import (
        AsyncSniffer, IP, TCP, UDP, ICMP, ARP,
        DNS, DNSQR, Ether, Raw,
        wrpcap, get_if_list
    )
except ImportError:
    print("Error: scapy not found. Install with: pip install scapy")
    sys.exit(1)


init(autoreset=True)

def print_banner():
    print(Fore.RED + Style.BRIGHT + "="*70)
    print(Fore.RED + Style.BRIGHT + "        ⚠ NETWORKPOSSUM - Network Sniffer Active ⚠")
    print(Fore.RED + Style.BRIGHT + "="*70)
    print(Fore.GREEN + "[+] Sniffing network traffic...")
    print(Fore.GREEN + "[+] Monitoring packets in real-time...")
    print(Fore.YELLOW + "[!] Use responsibly and ethically.")
    print(Fore.RED + "="*70 + "\n")

def check_privileges():
    if os.name == "nt":
        print("Note: For full packet capture functionality, run as Administrator.\n")

class PacketNode:
    def __init__(self, info):
        self.info = info
        self.next = None

class PacketLinkedList:
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

    def all_items(self):
        return zip(self.keys, self.values)

packet_list = PacketLinkedList()
bandwidth_ip = BandwidthMap()
bandwidth_proto = BandwidthMap()
stats = BandwidthMap()

raw_packets = []

# TCP stream buffer (for reconstructing split packets)
tcp_streams = {}

# credential keywords
CRED_KEYWORDS = [
    "username=", "password=", "passwd=", "pass=",
    "user=", "email=", "login=", "pwd=",
    "uname=", "userid="
]

TOKEN_KEYWORDS = [
    "session", "token", "auth", "jwt", "cookie"
]


def handle_packet(pkt):

    raw_packets.append(pkt)

    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    info = {"time": ts}

    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(IP):

        ip = pkt[IP]
        info.update({"src_ip": ip.src, "dst_ip": ip.dst})

        bandwidth_ip.add(ip.src, len(pkt))

        if pkt.haslayer(TCP):

            stats.add("TCP", 1)
            tcp = pkt[TCP]

            label = f"TCP {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}"
            info.update({"proto": "TCP", "detail": label})

            if pkt.haslayer(Raw):

                key = (ip.src, tcp.sport, ip.dst, tcp.dport)

                if key not in tcp_streams:
                    tcp_streams[key] = b""

                tcp_streams[key] += pkt[Raw].load

                payload = tcp_streams[key].decode(errors="ignore")

                # =========================
                # HTTP Request Detection
                # =========================

                if "GET " in payload or "POST " in payload:
                    print(Fore.CYAN + "\nHTTP Request Detected")

                # =========================
                # Credential Detection
                # =========================

                if any(k in payload.lower() for k in CRED_KEYWORDS):

                    info["warning"] = "⚠ Plaintext credentials detected!"

                    try:

                        body = payload.split("\r\n\r\n", 1)[-1]

                        parsed = urllib.parse.parse_qs(body)

                        creds = {}

                        for k, v in parsed.items():
                                creds[k] = v[0]

                        info["creds"] = creds

                    except:
                        info["creds"] = {"raw": payload[-200:]}

                # =========================
                # Cookie Capture
                # =========================

                if "cookie:" in payload.lower():

                    cookies = []

                    for line in payload.split("\r\n"):
                        if line.lower().startswith("cookie:"):
                            cookies.append(line)

                    if cookies:
                        info["cookies"] = cookies

                # =========================
                # Token / Session Detection
                # =========================

                if any(t in payload.lower() for t in TOKEN_KEYWORDS):

                    tokens = []

                    for line in payload.split("\n"):
                        if any(t in line.lower() for t in TOKEN_KEYWORDS):
                            tokens.append(line.strip())

                    if tokens:
                        info["tokens"] = tokens[:3]

            _print_packet(info)

        elif pkt.haslayer(UDP):

            stats.add("UDP", 1)

            udp = pkt[UDP]

            if pkt.haslayer(DNS):

                stats.add("DNS", 1)

                dns = pkt[DNS]

                if dns.qr == 0 and pkt.haslayer(DNSQR):

                    qname = pkt[DNSQR].qname.decode(errors="ignore")

                    info.update({
                        "proto": "DNS",
                        "detail": f"DNS Query {qname}"
                    })

                else:

                    info.update({
                        "proto": "DNS",
                        "detail": "DNS Response"
                    })

            else:

                info.update({
                    "proto": "UDP",
                    "detail": f"{ip.src}:{udp.sport} → {ip.dst}:{udp.dport}"
                })

            _print_packet(info)

        elif pkt.haslayer(ICMP):

            stats.add("ICMP", 1)

            info.update({
                "proto": "ICMP",
                "detail": f"{ip.src} → {ip.dst}"
            })

            _print_packet(info)

    packet_list.add_packet(info)

    bandwidth_proto.add(info.get("proto", "OTHER"), len(pkt))


# =========================
# Output
# =========================

def _print_packet(info):

    print(f"[{info.get('proto',''):<5}] {info.get('time')} {info.get('detail','')}")

    if "warning" in info:
        print(Fore.RED + f"   {info['warning']}")

    if "creds" in info:
        print(Fore.YELLOW + f"   Captured fields: {info['creds']}")

    if "cookies" in info:
        print(Fore.MAGENTA + f"   Cookies: {info['cookies']}")

    if "tokens" in info:
        print(Fore.BLUE + f"   Possible Tokens: {info['tokens']}")


def print_stats():

    print("\n" + "─"*50)
    print("Packet Summary")
    print("─"*50)

    for proto, count in stats.all_items():
        print(f"{proto:<6}: {count}")

    print("\nBandwidth per IP:")

    for ip, bw in bandwidth_ip.all_items():
        print(f"{ip:<15}: {bw} bytes")

    print("\nBandwidth per Protocol:")

    for proto, bw in bandwidth_proto.all_items():
        print(f"{proto:<6}: {bw} bytes")

    print("─"*50)


def list_interfaces():

    print("\nAvailable Interfaces:\n")

    for iface in get_if_list():
        print(f"  {iface}")


# =========================
# Main Menu
# =========================

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

            iface = input("Interface (blank for default): ").strip() or None
            bpf_filter = input("BPF Filter (optional): ").strip() or None

            print("\nPress Ctrl+C to stop capturing...\n")

            sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf_filter,
                prn=handle_packet,
                store=False
            )

            sniffer.start()

            try:
                while True:
                    pass
            except KeyboardInterrupt:

                print("\nStopping capture...")

                sniffer.stop()

        elif choice == "2":

            print_stats()

        elif choice == "3":

            list_interfaces()

        elif choice == "4":

            json_file = input("Enter JSON filename (optional): ").strip()
            pcap_file = input("Enter PCAP filename (optional): ").strip()

            if json_file:

                with open(json_file, "w") as f:
                    json.dump(list(packet_list.traverse()), f, indent=2)

                print(f"Saved JSON → {json_file}")

            if pcap_file:

                wrpcap(pcap_file, raw_packets)

                print(f"Saved PCAP → {pcap_file}")

        elif choice == "5":

            print("Exiting.")
            break

        else:

            print("Invalid choice.")


if __name__ == "__main__":
    main()