# Install scapy: pip install scapy
#Import sysytem and scapy functions
import sys
from scapy.all import *

# Define function to handle each packet
def handle_packet(packet):
    if packet.haslayer(TCP):
        handle_tcp_packet(packet)
    elif packet.haslayer(ICMP):
        handle_icmp_packet(packet)

# Define function to handle TCP packets, extracting both source and destination ip addresses and ports respectively
def handle_tcp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Define function to handle ICMP packets, extracting source and destinatin ip addresses and also ICMP type 
def handle_icmp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type
    print(f"ICMP Packet: {src_ip} -> {dst_ip}, Type: {icmp_type}")

# Main function to start packet sniffing
def main(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=handle_packet, store=0)

# Check if the script is being run directly
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    main(interface)


