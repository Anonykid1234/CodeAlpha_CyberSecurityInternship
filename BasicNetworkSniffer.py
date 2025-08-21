
from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        # Check transport layer
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        else:
            proto_name = str(proto)

        print(f"Source: {ip_src} --> Destination: {ip_dst} | Protocol: {proto_name}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload: {payload[:50]}")  # Print first 50 bytes
                print("-" * 60)

# Capture 20 packets (you can increase count or set count=0 for infinite)
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, count=20)
