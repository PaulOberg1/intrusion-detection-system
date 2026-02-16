#define _GNU_SOURCE
#include "control_server.h"
#include "globals.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define MAX_EVENTS 64
#define READ_BUF   4096
#define WRITE_BUF  4096

typedef struct client {
  int fd;
  char rbuf[READ_BUF];
  size_t rlen;

  char wbuf[WRITE_BUF];
  size_t wlen;
  size_t woff;
} client;

static pthread_t server_thread;
static int server_running = 0;

static int listen_fd = -1;
static int epfd = -1;

static control_server_config g_cfg = {0};

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return -1;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
  return 0;
}

static void close_client(client *c) {
  if (!c) return;
  if (c->fd >= 0) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->fd = -1;
  }
  free(c);
}

static void queue_write(client *c, const char *s) {
  if (!c || !s) return;
  size_t n = strlen(s);
  size_t space = (c->wlen < WRITE_BUF) ? (WRITE_BUF - c->wlen) : 0;
  size_t to_copy = (n < space) ? n : space;
  if (to_copy > 0) {
    memcpy(c->wbuf + c->wlen, s, to_copy);
    c->wlen += to_copy;
  }
}

static void modify_events(int fd, void *ptr, uint32_t events) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = events;
  ev.data.ptr = ptr;
  epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}

static void send_prompt(client *c) {
  queue_write(c, "\nids> ");
}

static void send_help(client *c) {
  queue_write(c,
    "Commands:\n"
    "  STATS   - show current IDS counters\n"
    "  RESET   - reset counters and SYN unique set\n"
    "  HELP    - show this help\n"
    "  QUIT    - close connection\n");
}

static void stats_snapshot(int *syn, int *unique_ips, int *arp, int *google, int *bbc) {
  pthread_mutex_lock(&syn_lock);
  *syn = syn_count;
  *unique_ips = syn_addresses ? syn_addresses->count : 0;
  pthread_mutex_unlock(&syn_lock);

  pthread_mutex_lock(&arp_lock);
  *arp = arp_count;
  pthread_mutex_unlock(&arp_lock);

  pthread_mutex_lock(&google_lock);
  *google = google_count;
  pthread_mutex_unlock(&google_lock);

  pthread_mutex_lock(&bbc_lock);
  *bbc = bbc_count;
  pthread_mutex_unlock(&bbc_lock);
}

static void reset_counters_and_set(void) {
  // Reset counters
  pthread_mutex_lock(&arp_lock);
  arp_count = 0;
  pthread_mutex_unlock(&arp_lock);

  pthread_mutex_lock(&google_lock);
  google_count = 0;
  pthread_mutex_unlock(&google_lock);

  pthread_mutex_lock(&bbc_lock);
  bbc_count = 0;
  pthread_mutex_unlock(&bbc_lock);

  // Reset SYN count + set (free buckets, re-init)
  pthread_mutex_lock(&syn_lock);
  syn_count = 0;

  if (syn_addresses) {
    free(syn_addresses->data);
    syn_addresses->data = calloc(SET_INITIAL_SIZE, sizeof(linkedlist));
    syn_addresses->count = 0;
  }

  pthread_mutex_unlock(&syn_lock);
}

static void handle_command(client *c, const char *line) {
  // Trim leading spaces
  while (*line == ' ' || *line == '\t') line++;

  if (strcasecmp(line, "STATS") == 0) {
    int syn, uniq, arp, google, bbc;
    stats_snapshot(&syn, &uniq, &arp, &google, &bbc);

    char out[512];
    snprintf(out, sizeof(out),
      "SYN packets: %d\n"
      "Unique SYN source IPs: %d\n"
      "ARP replies: %d\n"
      "Blacklist violations: %d (google=%d, bbc=%d)\n",
      syn, uniq, arp, google + bbc, google, bbc);

    queue_write(c, out);
  }
  else if (strcasecmp(line, "RESET") == 0) {
    reset_counters_and_set();
    queue_write(c, "OK: counters reset\n");
  }
  else if (strcasecmp(line, "HELP") == 0) {
    send_help(c);
  }
  else if (strcasecmp(line, "QUIT") == 0) {
    queue_write(c, "bye\n");
    // mark client for close by returning special token in caller
  }
  else if (*line == '\0') {
    // ignore empty
  }
  else {
    queue_write(c, "ERR: unknown command (try HELP)\n");
  }
}

static bool process_lines(client *c) {
  // returns true if client requested QUIT
  bool wants_quit = false;

  size_t start = 0;
  for (;;) {
    char *nl = memchr(c->rbuf + start, '\n', c->rlen - start);
    if (!nl) break;

    size_t linelen = (size_t)(nl - (c->rbuf + start));
    // handle optional \r
    if (linelen > 0 && c->rbuf[start + linelen - 1] == '\r') linelen--;

    char line[1024];
    size_t copy = (linelen < sizeof(line) - 1) ? linelen : (sizeof(line) - 1);
    memcpy(line, c->rbuf + start, copy);
    line[copy] = '\0';

    if (strcasecmp(line, "QUIT") == 0) wants_quit = true;
    handle_command(c, line);

    start = (size_t)((nl - c->rbuf) + 1);
  }

  // Shift remaining bytes to front
  if (start > 0) {
    size_t rem = c->rlen - start;
    memmove(c->rbuf, c->rbuf + start, rem);
    c->rlen = rem;
  }

  return wants_quit;
}

static void accept_clients(void) {
  for (;;) {
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    int cfd = accept(listen_fd, (struct sockaddr *)&addr, &alen);
    if (cfd == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      if (errno == EINTR) continue;
      perror("accept");
      return;
    }

    if (set_nonblocking(cfd) == -1) {
      close(cfd);
      continue;
    }

    client *c = calloc(1, sizeof(client));
    c->fd = cfd;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.ptr = c;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev) == -1) {
      close(cfd);
      free(c);
      continue;
    }

    queue_write(c, "Welcome to IDS control.\nType HELP for commands.\n");
    send_prompt(c);
    // ensure EPOLLOUT is enabled if there is data to send
    modify_events(cfd, c, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
  }
}

static void flush_writes(client *c) {
  while (c->woff < c->wlen) {
    ssize_t n = write(c->fd, c->wbuf + c->woff, c->wlen - c->woff);
    if (n > 0) {
      c->woff += (size_t)n;
      continue;
    }
    if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    }
    c->wlen = 0;
    c->woff = 0;
    return;
  }

  c->wlen = 0;
  c->woff = 0;
}

static void *server_main(void *arg) {
  (void)arg;

  epfd = epoll_create1(0);
  if (epfd == -1) {
    perror("epoll_create1");
    return NULL;
  }

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd == -1) {
    perror("socket");
    close(epfd);
    epfd = -1;
    return NULL;
  }

  int one = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  if (set_nonblocking(listen_fd) == -1) {
    perror("fcntl");
    close(listen_fd);
    listen_fd = -1;
    close(epfd);
    epfd = -1;
    return NULL;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)g_cfg.port);

  if (!g_cfg.bind_ip) g_cfg.bind_ip = "127.0.0.1";
  if (inet_pton(AF_INET, g_cfg.bind_ip, &addr.sin_addr) != 1) {
    fprintf(stderr, "inet_pton failed for bind ip: %s\n", g_cfg.bind_ip);
    close(listen_fd);
    listen_fd = -1;
    close(epfd);
    epfd = -1;
    return NULL;
  }

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("bind");
    close(listen_fd);
    listen_fd = -1;
    close(epfd);
    epfd = -1;
    return NULL;
  }

  if (!g_cfg.backlog) g_cfg.backlog = 128;
  if (listen(listen_fd, g_cfg.backlog) == -1) {
    perror("listen");
    close(listen_fd);
    listen_fd = -1;
    close(epfd);
    epfd = -1;
    return NULL;
  }

  // Register listening socket
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  ev.data.ptr = NULL;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) == -1) {
    perror("epoll_ctl ADD listen");
    close(listen_fd);
    listen_fd = -1;
    close(epfd);
    epfd = -1;
    return NULL;
  }

  server_running = 1;
  fprintf(stderr, "Control server listening on %s:%d\n", g_cfg.bind_ip, g_cfg.port);

  struct epoll_event events[MAX_EVENTS];

  while (loop) {
    int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
    if (n == -1) {
      if (errno == EINTR) continue;
      perror("epoll_wait");
      break;
    }

    for (int i = 0; i < n; i++) {
      if (events[i].data.ptr == NULL) {
        // listener
        accept_clients();
        continue;
      }

      client *c = (client *)events[i].data.ptr;
      uint32_t e = events[i].events;

      if (e & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
        close_client(c);
        continue;
      }

      bool wants_quit = false;

      if (e & EPOLLIN) {
        for (;;) {
          ssize_t r = read(c->fd, c->rbuf + c->rlen, READ_BUF - c->rlen);
          if (r > 0) {
            c->rlen += (size_t)r;
            // If buffer fills then process what is possible
            if (c->rlen == READ_BUF) {
              wants_quit |= process_lines(c);
              break;
            }
            continue;
          }
          if (r == 0) {
            close_client(c);
            c = NULL;
            break;
          }
          if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
          }
          if (r == -1 && errno == EINTR) continue;

          close_client(c);
          c = NULL;
          break;
        }
        if (!c) continue;

        wants_quit |= process_lines(c);
        send_prompt(c);
      }

      if (c && (e & EPOLLOUT)) {
        flush_writes(c);
      }

      if (!c) continue;

      // adjust epoll interest
      uint32_t want = EPOLLIN | EPOLLRDHUP;
      if (c->wlen > c->woff) want |= EPOLLOUT;
      modify_events(c->fd, c, want);

      if (wants_quit && c->wlen == 0) {
        close_client(c);
      }
    }
  }

  // shutdown
  if (listen_fd >= 0) {
    epoll_ctl(epfd, EPOLL_CTL_DEL, listen_fd, NULL);
    close(listen_fd);
    listen_fd = -1;
  }
  if (epfd >= 0) {
    close(epfd);
    epfd = -1;
  }
  server_running = 0;
  return NULL;
}

int control_server_start(const control_server_config *cfg, pthread_t *thread_out) {
  if (!cfg) return -1;
  g_cfg = *cfg;

  if (pthread_create(&server_thread, NULL, server_main, NULL) != 0) {
    return -1;
  }
  if (thread_out) *thread_out = server_thread;
  return 0;
}

void control_server_stop(void) {
  if (server_thread) {
    pthread_join(server_thread, NULL);
    server_thread = (pthread_t)0;
  }
}
