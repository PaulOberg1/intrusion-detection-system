# High-Throughput Intrusion Detection System (IDS)

A high-performance, multithreaded packet inspection pipeline written in C, designed to explore scalable network processing on Linux using libpcap, epoll, and POSIX threading.

## Features

- High-throughput packet capture using libpcap
- Custom pthread-based thread pool
- Lock-protected producer–consumer queue
- Nonblocking epoll-based TCP control server
- Batched processing to reduce synchronization overhead
- Memory and race-condition validation with Valgrind and gdb

## Architecture

The system is structured as a producer–consumer pipeline:

1. **Packet Capture Thread**
   - Captures packets via libpcap
   - Enqueues work into a shared queue

2. **Worker Thread Pool**
   - Processes packets in parallel
   - Uses condition variables for coordination
   - Minimises contention via batching

3. **Control Server**
   - epoll-based nonblocking TCP server
   - Provides real-time statistics queries

## Performance Focus

Key optimisation techniques:

- Careful mutex scoping in hot paths
- Batched dequeues to reduce wakeups
- Nonblocking I/O with epoll
- Cache-friendly queue access patterns

## Build

```bash
make
