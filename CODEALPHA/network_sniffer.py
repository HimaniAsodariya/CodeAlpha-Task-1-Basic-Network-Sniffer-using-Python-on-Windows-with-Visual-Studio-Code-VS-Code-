from scapy.all import sniff, Ether, IP, TCP

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
