EV
==

Light event-loop library loosely inspired by the excellent libuv, in a single
**small** (< 600 sloc) header, based on the common IO multiplexing
imlementations available, epoll on linux, kqueue on BSD-like and OSX,
poll/select as a fallback, dependencies-free.

## Running examples

A simple event-driven echo server

```
$ make echo-server
```

Write periodically on the screen `ping` and `pong` on different frequencies,
referred as cron tasks

```
$ make ping-pong
```
