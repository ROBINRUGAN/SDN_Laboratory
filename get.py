from scapy.all import *
from scapy.layers.inet import IP

def packet_fun(packet):
    if packet.haslayer(Raw):
        try:
            data = packet[Raw].load.decode()
        except:
            data = "unknown"
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print("Received:", data, src_ip, dst_ip)


filter_rule = "udp and dst host 192.168.189.131"
packets = sniff(filter=filter_rule, prn=packet_fun, count=10000)

wrpcap("packages.pcap", packets)
