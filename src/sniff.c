#include "sniff.h"
#include "globals.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>

#include "dispatch.h"
#include "control_server.h"

#define THREADPOOL_SIZE 10

int v;
pcap_t *pcap_handle;

void handler(int signal) {
  (void)signal;
  pcap_breakloop(pcap_handle);
  loop = 0;
}

void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
  (void)args;
  if (v) {
    dump(packet, header->len);
  }
  dispatch(header, packet, v);
}

void sniff(char *interface, int verbose) {

  int i;
  char errbuf[PCAP_ERRBUF_SIZE] = "";

  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  if (strcmp("", errbuf) != 0) {
    fprintf(stderr, "%s", errbuf);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  v = verbose;

  // Set intrusion records
  syn_addresses = malloc(sizeof(set));
  syn_addresses->data = calloc(SET_INITIAL_SIZE, sizeof(linkedlist));
  syn_addresses->count = 0;

  syn_count = 0;
  arp_count = 0;
  google_count = 0;
  bbc_count = 0;

  // Initialise mutex, cond variables
  pthread_mutex_init(&syn_lock, NULL);
  pthread_mutex_init(&arp_lock, NULL);
  pthread_mutex_init(&google_lock, NULL);
  pthread_mutex_init(&bbc_lock, NULL);
  pthread_mutex_init(&qlock, NULL);
  pthread_cond_init(&qcond, NULL);

  // Sets loop to 1 for use in threads
  loop = 1;

  // Initialise values of queue
  q.head = NULL;
  q.tail = NULL;

  // Set signal
  signal(SIGINT, handler);

  // Start control server (epoll + TCP)
  pthread_t ctl_thread;
  control_server_config cfg = {
    .bind_ip = "127.0.0.1",
    .port = 9090,
    .backlog = 128
  };
  if (control_server_start(&cfg, &ctl_thread) != 0) {
    fprintf(stderr, "Warning: failed to start control server\n");
  } else {
    fprintf(stderr, "Control server: connect via `nc 127.0.0.1 9090`\n");
  }

  // Create worker threads
  pthread_t threads[THREADPOOL_SIZE];
  for (i = 0; i < THREADPOOL_SIZE; i++) {
    pthread_create(&threads[i], NULL, &thread_handler, NULL);
  }

  // Capture loop
  pcap_loop(pcap_handle, 0, (pcap_handler)handle_packet, NULL);

  // Wake threads; allow them to drain queue then exit
  pthread_cond_broadcast(&qcond);

  for (i = 0; i < THREADPOOL_SIZE; i++) {
    pthread_join(threads[i], NULL);
  }

  // Stop control server thread (it exits when loop==0)
  control_server_stop();

  printf("\nIntrusion Detection Report:\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n", syn_count, syn_addresses->count);
  printf("%d ARP responses (cache poisoning)\n", arp_count);
  printf("%d URL Blacklist violations (%d google and %d bbc)\n", google_count + bbc_count, google_count, bbc_count);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;

  struct ether_header *eth_header = (struct ether_header *)data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) printf(":");
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) printf(":");
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);

  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20;
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    for (i = 0; i < output_sz; ++i) {
      if (i < (unsigned)output_bytes) printf("%02x ", payload[i]);
      else printf("   ");
    }
    printf("| ");
    for (i = 0; i < (unsigned)output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) printf("%c", byte);
      else printf(".");
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
