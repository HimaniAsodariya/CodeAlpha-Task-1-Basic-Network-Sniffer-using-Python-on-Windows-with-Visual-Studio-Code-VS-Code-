# CodeAlpha Task 1: Basic Network Sniffer

## Objective
Create a Python network sniffer that captures and displays live network packet headers (Ethernet, IP, and TCP) on Windows.

## Tools
- Python 3
- Scapy
- VS Code on Windows

## How to Run
## 1. Install Required Software
Open PowerShell or VS Code terminal and run pip install scapy 
## 2. Write the Sniffer Script 
Create a folder (e.g., codealpha_tasks)
Inside it, create a new file: network_sniffer.py

Paste this code below:
## from scapy.all import sniff, Ether, IP, TCP

def packet_callback(packet):
    if packet.haslayer(Ether):
        ether = packet.getlayer(Ether)
        print(f"\nEthernet Frame:")
        print(f"  Source MAC: {ether.src}")
        print(f"  Destination MAC: {ether.dst}")

    if packet.haslayer(IP):
        ip = packet.getlayer(IP)
        print(f"  IP Packet:")
        print(f"    Source IP: {ip.src}")
        print(f"    Destination IP: {ip.dst}")
        print(f"    Protocol: {ip.proto}")

    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        print(f"    TCP Segment:")
        print(f"      Source Port: {tcp.sport}")
        print(f"      Destination Port: {tcp.dport}")

print("[*] Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
## 3. Run the Script
Open the terminal in VS Code: Terminal → New Terminal
Run it as Administrator (important for packet sniffing)
Type:
python network_sniffer.py

## Here you go 

## You’ll start seeing live traffic
