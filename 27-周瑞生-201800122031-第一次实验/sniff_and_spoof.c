#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "myheader.h"
#include <stdlib.h>


unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip);

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/

/* Ethernet header */
// struct ethheader {
//   u_char  ether_dhost[6]; /* destination host address */
//   u_char  ether_shost[6]; /* source host address */
//   u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
// };

// /* IP Header */
// struct ipheader {
//   unsigned char      iph_ihl:4, //IP header length
//                      iph_ver:4; //IP version
//   unsigned char      iph_tos; //Type of service
//   unsigned short int iph_len; //IP Packet length (data + header)
//   unsigned short int iph_ident; //Identification
//   unsigned short int iph_flag:3, //Fragmentation flags
//                      iph_offset:13; //Flags offset
//   unsigned char      iph_ttl; //Time to Live
//   unsigned char      iph_protocol; //Protocol type
//   unsigned short int iph_chksum; //IP datagram checksum
//   struct  in_addr    iph_sourceip; //Source IP address
//   struct  in_addr    iph_destip;   //Destination IP address
// };

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800)
  {

      	struct ipheader * ip0 = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
  		printf("       From: %s\n", inet_ntoa(ip0->iph_sourceip));   

   		printf("         To: %s\n", inet_ntoa(ip0->iph_destip)); 

 switch(ip0->iph_protocol) 
 {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
struct icmpheader*Icmp=(struct icmpheader*)(packet + sizeof(struct ethheader)+ip0->iph_ihl*4);

             char *buffer=(char *)malloc(1500);
            if (!buffer)
             {
            	printf("Malloc error!\n");
            	exit(-1);
           }
      		 memset(buffer, 0, 1500);
      
      /*********************************************************
          Step 2: Fill in the IP header.
        ********************************************************/
      struct ipheader *ip = (struct ipheader *) buffer;

      ip->iph_ver = 4;
      ip->iph_ihl = 5;
      ip->iph_ttl = 20;
      ip->iph_sourceip.s_addr = inet_addr( inet_ntoa(ip0->iph_destip));
      ip->iph_destip.s_addr = inet_addr(inet_ntoa(ip0->iph_sourceip));
      ip->iph_protocol = IPPROTO_ICMP;
      ip->iph_len = htons(sizeof(struct ipheader) +
                          sizeof(struct icmpheader));


		// /*********************************************************
  //         Step 1: Fill in the ICMP header.
  //       ********************************************************/
      struct icmpheader *icmp = (struct icmpheader *)
                                (buffer + sizeof(struct ipheader));
      icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
        icmp->icmp_seq=Icmp->icmp_seq;
  		icmp->icmp_id=htons(4321);
      // Calculate the checksum for integrity
      icmp->icmp_chksum = 0;
      icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                    sizeof(struct icmpheader));
    





  //     /*********************************************************
  //         Step 3: Finally, send the spoofed packet
  //       ********************************************************/
      send_raw_ip_packet (ip);
      printf("Send Success!\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }




  }
  }

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp ";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


