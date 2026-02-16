#include "dispatch.h"
#include "globals.h"

#include <pcap.h>
#include <stdlib.h>

#include "analysis.h"

#define BATCH_SIZE 32

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  args *a = malloc(sizeof(args));
  a->header = header;
  a->packet = packet;
  a->verbose = verbose;

  pthread_mutex_lock(&qlock);
  enqueue(&q, a);
  pthread_cond_broadcast(&qcond);
  pthread_mutex_unlock(&qlock);
}

void *thread_handler(void *arg) {
  (void)arg;

  while (loop || !isEmpty(&q)) {
    args *batch[BATCH_SIZE];
    int n = 0;

    pthread_mutex_lock(&qlock);
    while (isEmpty(&q) && loop) {
      pthread_cond_wait(&qcond, &qlock);
    }

    while (!isEmpty(&q) && n < BATCH_SIZE) {
      batch[n++] = dequeue(&q);
    }
    pthread_mutex_unlock(&qlock);

    // Process outside lock
    for (int i = 0; i < n; i++) {
      analyse(batch[i]->header, batch[i]->packet, batch[i]->verbose);
      free(batch[i]);
    }
  }
  return NULL;
}
