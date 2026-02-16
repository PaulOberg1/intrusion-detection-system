#include "analysis.h"
#include "globals.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>


void analyse(const struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

  struct ether_header *eth_header = (struct ether_header *) packet;
  if (ntohs(eth_header->ether_type) == 0x0800) { //Protocol of next layer is IP
    struct iphdr *ih = (struct iphdr *) (packet + ETH_HLEN);
    if (ih->protocol == 6) { //Protocol of next layer is TCP
      unsigned int size_ih = 4*(ih->ihl);
      struct tcphdr *th = (struct tcphdr *) (packet + ETH_HLEN + size_ih);
      if (th->th_flags & 2) { //TCP packet is a SYN packet
        pthread_mutex_lock(&syn_lock);
        syn_count++;
        if (!check_member(syn_addresses, ih->saddr)) {
          add(syn_addresses, ih->saddr);
        }
        pthread_mutex_unlock(&syn_lock);
      }
      if (ntohs(th->th_dport) == 80) { //Packet sent to port 80
        char *http = (char *) packet+ETH_HLEN+size_ih+4*(th->th_off);
        char *end = strstr(http, "\r\n\r\n"); //HTTP header will end with \r\n\r\n
        if (end) {
          char *google_ptr = strstr(http, "Host: www.google.co.uk");
          char *bbc_ptr = strstr(http, "Host: www.bbc.co.uk");
          if (google_ptr != NULL && google_ptr < end) {
            print_blacklist(&ih->saddr, &ih->daddr, "google");
            pthread_mutex_lock(&google_lock);
            google_count++;
            pthread_mutex_unlock(&google_lock);
          } //Check if blacklisted URLs are inside the HTTP header
          if (bbc_ptr != NULL && bbc_ptr < end) {
            print_blacklist(&ih->saddr, &ih->daddr, "bbc");
            pthread_mutex_lock(&bbc_lock);
            bbc_count++;
            pthread_mutex_unlock(&bbc_lock);
          }
        }
      }
    }
  } else if (ntohs(eth_header->ether_type) == 0x0806) { //Protocol of next layer is ARP
    struct ether_arp *ah = (struct ether_arp *) (packet+ETH_HLEN);
    if (ntohs((ah->ea_hdr).ar_op) == 2) { //ARP packet is reply
      pthread_mutex_lock(&arp_lock);
      arp_count++;
      pthread_mutex_unlock(&arp_lock);
    }
  }
}

void print_blacklist(uint32_t *saddr, uint32_t *daddr, char *website) {
  int i;

  printf("==============================\n");
  printf("Blacklisted URL violation detected\n");

  printf("Source IP address: ");
  uint8_t *srcaddr = (uint8_t *) saddr;
  for (i = 0; i < 4; i++) {
    printf("%d", srcaddr[i]);
    if (i < 3) {
      printf(".");
    }
  }
  printf("\n");

  printf("Destination IP address: ");
  uint8_t *destaddr = (uint8_t *) daddr;
  for (i = 0; i < 4; i++) {
    printf("%d", destaddr[i]);
    if (i < 3) {
      printf(".");
    }
  }
  printf(" (%s)\n", website);
  
  printf("==============================\n");
}