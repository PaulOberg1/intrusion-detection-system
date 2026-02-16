#include "globals.h"

set *syn_addresses;
int syn_count;
pthread_mutex_t syn_lock;
int arp_count;
pthread_mutex_t arp_lock;
int google_count;
pthread_mutex_t google_lock;
int bbc_count;
pthread_mutex_t bbc_lock;

queue q;
pthread_mutex_t qlock;
pthread_cond_t qcond;
volatile int loop;