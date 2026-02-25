#!/usr/bin/env python3
"""
Network Sniffer - Educational packet capture tool
Requires: pip install scapy
Must be run with root/administrator privileges
Usage: sudo python3 network_sniffer.py [options]
"""

import argparse
import sys
import datetime
import json
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Ether, wrpcap, rdpcap, get_if_list
    )
except ImportError:
    print("Error: scapy not found. Install it with: pip install scapy")
    sys.exit(1)


# ─── Stats ────────────────────────────────────────────────────────────────────

stats = defaultdict(int)
packet_log = []


# ─── Packet Handler ───────────────────────────────────────────────────────────

def handle_packet(packet, verbose=False, output_file=None, log_json=False):
    """Parse and display a captured packet."""
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    info = {"time": ts}

    stats["total"] += 1

    # ── Ethernet ──
    if packet.haslayer(Ether):
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # ── ARP ──
    if packet.haslayer(ARP):
        stats["arp"] += 1
        arp = packet[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        info["proto"] = "ARP"
        info["detail"] = f"{op} {arp.psrc} → {arp.pdst}"
        _print_packet(info, "ARP", verbose)

    # ── IP ──
    elif packet.haslayer(IP):
        ip = packet[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        info["ttl"] = ip.ttl

        # TCP
        if packet.haslayer(TCP):
            stats["tcp"] += 1
            tcp = packet[TCP]
            flags = _tcp_flags(tcp.flags)
            info["proto"] = "TCP"
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            info["flags"] = flags
            payload_len = len(tcp.payload)
            info["payload_len"] = payload_len
            service = _guess_service(tcp.sport, tcp.dport)
            info["service"] = service
            label = f"TCP [{flags}] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}"
            if service:
                label += f"  ({service})"
            if payload_len:
                label += f"  {payload_len}B"
            info["detail"] = label
            _print_packet(info, "TCP", verbose)

        # UDP / DNS
        elif packet.haslayer(UDP):
            stats["udp"] += 1
            udp = packet[UDP]
            info["proto"] = "UDP"
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport

            if packet.haslayer(DNS):
                stats["dns"] += 1
                dns = packet[DNS]
                if dns.qr == 0 and packet.haslayer(DNSQR):  # Query
                    qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                    info["proto"] = "DNS"
                    info["detail"] = f"QUERY {qname}"
                elif dns.qr == 1 and packet.haslayer(DNSRR):  # Response
                    qname = packet[DNSRR].rrname.decode(errors="replace").rstrip(".")
                    rdata = packet[DNSRR].rdata
                    info["proto"] = "DNS"
                    info["detail"] = f"REPLY  {qname} → {rdata}"
                else:
                    info["detail"] = "DNS (unknown)"
                _print_packet(info, "DNS", verbose)
            else:
                service = _guess_service(udp.sport, udp.dport)
                info["service"] = service
                label = f"UDP {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}"
                if service:
                    label += f"  ({service})"
                info["detail"] = label
                _print_packet(info, "UDP", verbose)

        # ICMP
        elif packet.haslayer(ICMP):
            stats["icmp"] += 1
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                          11: "Time Exceeded", 5: "Redirect"}
            t = icmp_types.get(icmp.type, f"type={icmp.type}")
            info["proto"] = "ICMP"
            info["detail"] = f"ICMP {t}  {ip.src} → {ip.dst}"
            _print_packet(info, "ICMP", verbose)

        else:
            stats["other"] += 1
            info["proto"] = f"IP/{ip.proto}"
            info["detail"] = f"{ip.src} → {ip.dst}"
            _print_packet(info, "OTHER", verbose)

    else:
        stats["other"] += 1

    # Save to log
    if log_json:
        packet_log.append(info)


def _tcp_flags(flags):
    flag_map = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
                "P": "PSH", "U": "URG"}
    return "|".join(v for k, v in flag_map.items() if k in str(flags))


def _guess_service(sport, dport):
    services = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
        110: "POP3", 143: "IMAP", 53: "DNS", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3389: "RDP", 23: "Telnet",
    }
    return services.get(dport) or services.get(sport) or ""


COLORS = {
    "TCP":   "\033[94m",   # blue
    "UDP":   "\033[96m",   # cyan
    "DNS":   "\033[93m",   # yellow
    "ICMP":  "\033[95m",   # magenta
    "ARP":   "\033[92m",   # green
    "OTHER": "\033[90m",   # dark grey
    "RESET": "\033[0m",
}


def _print_packet(info, proto, verbose):
    color = COLORS.get(proto, "")
    reset = COLORS["RESET"]
    detail = info.get("detail", "")
    ts = info.get("time", "")
    print(f"  {color}[{proto:<5}]{reset} {ts}  {detail}")
    if verbose:
        for k, v in info.items():
            if k not in ("proto", "detail", "time"):
                print(f"           {k}: {v}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def print_stats():
    print("\n" + "─" * 50)
    print("  Packet Summary")
    print("─" * 50)
    print(f"  Total:  {stats['total']}")
    print(f"  TCP:    {stats['tcp']}")
    print(f"  UDP:    {stats['udp']}")
    print(f"  DNS:    {stats['dns']}")
    print(f"  ICMP:   {stats['icmp']}")
    print(f"  ARP:    {stats['arp']}")
    print(f"  Other:  {stats['other']}")
    print("─" * 50)


def list_interfaces():
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  {iface}")


def main():
    parser = argparse.ArgumentParser(
        description="Network Sniffer — educational packet capture tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_sniffer.py
  sudo python3 network_sniffer.py -i eth0 -n 100
  sudo python3 network_sniffer.py -f "tcp port 443" -v
  sudo python3 network_sniffer.py -n 50 --save capture.pcap
  sudo python3 network_sniffer.py --read capture.pcap
  python3 network_sniffer.py --list-interfaces
        """
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff on (default: all)")
    parser.add_argument("-n", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF filter string e.g. 'tcp port 80'")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed packet fields")
    parser.add_argument("--save", metavar="FILE",
                        help="Save captured packets to a .pcap file")
    parser.add_argument("--read", metavar="FILE",
                        help="Read packets from a .pcap file instead of live capture")
    parser.add_argument("--log-json", metavar="FILE",
                        help="Save parsed packet info to a JSON file")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    print("╔══════════════════════════════════════╗")
    print("║        Network Sniffer v1.0          ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Interface : {args.interface or 'all'}")
    print(f"  Filter    : {args.filter or 'none'}")
    print(f"  Count     : {args.count or 'unlimited'}")
    print(f"  Verbose   : {args.verbose}")
    if args.save:
        print(f"  Save to   : {args.save}")
    print("\n  Press Ctrl+C to stop\n")
    print("─" * 50)

    captured = []

    def handler(pkt):
        handle_packet(pkt, verbose=args.verbose, log_json=bool(args.log_json))
        if args.save:
            captured.append(pkt)

    try:
        if args.read:
            print(f"  Reading from {args.read}...\n")
            packets = rdpcap(args.read)
            for pkt in packets:
                handler(pkt)
        else:
            sniff(
                iface=args.interface,
                filter=args.filter,
                count=args.count,
                prn=handler,
                store=False,
            )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n  ⚠ Permission denied. Run with sudo/administrator privileges.")
        sys.exit(1)

    print_stats()

    if args.save and captured:
        wrpcap(args.save, captured)
        print(f"\n  Saved {len(captured)} packets → {args.save}")

    if args.log_json and packet_log:
        with open(args.log_json, "w") as f:
            json.dump(packet_log, f, indent=2, default=str)
        print(f"  JSON log saved → {args.log_json}")


if __name__ == "__main__":
    main()