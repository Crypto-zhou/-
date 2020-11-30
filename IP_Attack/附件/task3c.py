#!/usr/bin/python3
from scapy.all import *
import random
# 1.   
ip = IP(src="10.0.2.4", dst="192.168.60.4")
ip.id = 0x1111 # Identification
ip.frag = 0 # Offset of this IP fragment
ip.flags = 0 # Flags
# Construct UDP header
udp = UDP(sport=7070, dport=9090,len=40,chksum=0)
# Construct payload
payload = 'A' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)
# 2.   
ip = IP(src="192.168.60.2", dst="192.168.60.4")
ip.id = 0x1111 # Identification
ip.frag = 0 # Offset of this IP fragment
ip.flags = 0 # Flags
# Construct UDP header
udp = UDP(sport=7070, dport=9090,len=40,chksum=0)
# Construct payload
payload = 'B' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)
# 3.   
ip = IP(src="1.2.3.4", dst="192.168.60.4")
ip.id = 0x1111 # Identification
ip.frag = 0 # Offset of this IP fragment
ip.flags = 0 # Flags
# Construct UDP header
udp = UDP(sport=7070, dport=9090,len=40,chksum=0)
# Construct payload
payload = 'C' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)