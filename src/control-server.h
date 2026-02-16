#ifndef CS241_CONTROL_SERVER_H
#define CS241_CONTROL_SERVER_H

#include <pthread.h>

typedef struct control_server_config {
  const char *bind_ip;   // e.g. "127.0.0.1"
  int port;              // e.g. 9090
  int backlog;           // e.g. 128
} control_server_config;

int control_server_start(const control_server_config *cfg, pthread_t *thread_out);
void control_server_stop(void);

#endif
