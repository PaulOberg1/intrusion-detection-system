#include "hashset.h"
#include "queue.h"
#include <pthread.h>

extern set *syn_addresses;
extern int syn_count;
extern pthread_mutex_t syn_lock;
extern int arp_count;
extern pthread_mutex_t arp_lock;
extern int google_count;
extern pthread_mutex_t google_lock;
extern int bbc_count;
extern pthread_mutex_t bbc_lock;

extern queue q;
extern pthread_mutex_t qlock;
extern pthread_cond_t qcond;
extern volatile int loop;