import random

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandIP

for _ in range(10000):
    packet = IP(src="192.168.189."+str(random.randint(0,255)), dst="192.168.189.131") / UDP() / Raw(load="MEWWW")
    send(packet)
