#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>

void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void *thread_handler(void *arg);

#endif
