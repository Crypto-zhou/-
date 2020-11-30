#!/usr/bin/python3
from scapy.all import *
# Construct the first IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000  # Identification
ip.frag = 0  # Offset of this IP fragment
ip.flags = 1 # Flags
udp =UDP(sport=7070, dport=9090,len=104,chksum = 0)# Construct UDP header
payload = 'A' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)

# Construct the Second IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000
ip.frag=5
ip.flags=1
ip.proto=17
payload = 'B' * 32
pkt=ip/payload
send(pkt, verbose=0)
# Construct the 3rd IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000
ip.frag=9
ip.flags=0
ip.proto=17
payload = 'C' * 32
pkt=ip/payload
send(pkt, verbose=0)
\end{lstlisting}

\section{task1b\ (1)}
	\begin{lstlisting}[language=python]
#!/usr/bin/python3
from scapy.all import *
# Construct the first IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000  # Identification
ip.frag = 0  # Offset of this IP fragment
ip.flags = 1 # Flags
udp =UDP(sport=7070, dport=9090,len=88,chksum = 0)# Construct UDP header
payload = 'A' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt = ip/udp/payload # For other fragments, we should use ip/payload
send(pkt, verbose=0)

# Construct the Second IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000
ip.frag=3
ip.flags=1
ip.proto=17
payload = 'B' * 32
pkt=ip/payload
send(pkt, verbose=0)
# Construct the 3rd IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5")
ip.id = 1000
ip.frag=7
ip.flags=0
ip.proto=17
payload = 'C' * 32
pkt=ip/payload
send(pkt, verbose=0)