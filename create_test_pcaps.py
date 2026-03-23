from scapy.all import IP, TCP, wrpcap
import os

base_dir = r"c:\Users\amogh\Desktop\AvaDump\test_pcap"
os.makedirs(base_dir, exist_ok=True)
path = os.path.join(base_dir, "attacks.pcap")

packets = []

# Normal HTTP
packets.append(IP(src="192.168.1.100", dst="103.10.28.50")/TCP(sport=54321, dport=80, flags="S"))

# SSH brute force
for i in range(6):
    packets.append(IP(src="10.1.1.50", dst="192.168.1.200")/TCP(sport=60000, dport=22, flags="S"))

# Port scan
for i in range(8):
    packets.append(IP(src="203.0.113.10", dst="192.168.1.10")/TCP(sport=1234, dport=20+i, flags="S"))

# SYN flood / DoS
for i in range(10):
    packets.append(IP(src=f"1.2.3.{i+10}", dst="192.168.1.50")/TCP(sport=8000+i, dport=80, flags="S"))

wrpcap(path, packets)
print(f"Saved: {path}")