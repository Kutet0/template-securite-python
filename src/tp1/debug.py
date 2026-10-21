from scapy.all import rdpcap, ARP

packets = rdpcap("/workspace/tp1-grp-4-191ba9.pcap")

ip_macs = {}
for packet in packets:
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip not in ip_macs:
            ip_macs[ip] = set()
        ip_macs[ip].add(mac)
print(ip_macs)