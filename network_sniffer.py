
from scapy.all import *

def analyze_packet(packet):
    if Ether in packet:
        print("Ethernet Header:")
        print(f" - Destination MAC: {packet[Ether].dst}")
        print(f" - Source MAC: {packet[Ether].src}")
        print(f" - Protocol: {packet[Ether].type}")

    if IP in packet:
        print("IP Header:")
        print(f" - Version: {packet[IP].version}")
        print(f" - Header Length: {packet[IP].ihl * 4}")
        print(f" - TTL: {packet[IP].ttl}")
        print(f" - Source IP: {packet[IP].src}")
        print(f" - Destination IP: {packet[IP].dst}")

    if TCP in packet:
        print("TCP Header:")
        print(f" - Source Port: {packet[TCP].sport}")
        print(f" - Destination Port: {packet[TCP].dport}")
        print(f" - Sequence Number: {packet[TCP].seq}")
        print(f" - Acknowledgment Number: {packet[TCP].ack}")
        print(f" - Header Length: {packet[TCP].dataofs * 4}")
        print(f" - Flags: {packet[TCP].flags}")

    if UDP in packet:
        print("UDP Header:")
        print(f" - Source Port: {packet[UDP].sport}")
        print(f" - Destination Port: {packet[UDP].dport}")
        print(f" - Length: {packet[UDP].len}")

    if ICMP in packet:
        print("ICMP Header:")
        print(f" - Type: {packet[ICMP].type}")
        print(f" - Code: {packet[ICMP].code}")

# Sniff incoming packets
sniff(prn=analyze_packet)