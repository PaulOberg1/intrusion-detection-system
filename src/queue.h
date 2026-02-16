#include <pcap.h>

typedef struct arguments {
  const struct pcap_pkthdr *header;
  const unsigned char *packet;
  int verbose;
} args;

typedef struct Queue {
    struct element *head;
	struct element *tail;
} queue;

int isEmpty(queue *queue);

void enqueue(queue *queue, args *val);

args *dequeue(queue *queue);