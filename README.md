EV
==

Light event-loop library loosely inspired by the excellent libuv, in a single
**small** (< 1000 sloc) header, based on the common IO multiplexing
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

### Helper APIs

```c
#include <stdio.h>
#include <stdlib.h>
#include "../ev.h"

static void on_data(ev_tcp_client *client) {
    ev_tcp_read(client);
    printf("Received %li bytes\n", client->bufsize);
    if (strncmp(client->buf, "quit", 4) == 0)
        ev_tcp_close_connection(client);
    else
        ev_tcp_write(client);
}

static void on_connection(ev_tcp_server *server) {
    ev_tcp_client *client = malloc(sizeof(*client));
    ev_tcp_server_accept(server, client, on_data);
}

int main(void) {

    ev_context *ctx = ev_get_ev_context();
    ev_tcp_server server;
    ev_tcp_server_init(&server, ctx, 128);
    ev_tcp_server_listen(&server, "127.0.0.1", 5959, on_connection);
    ev_tcp_server_stop(&server);

    return 0;
}
```

## Roadmap

- UDP helper APIs
- TLS setup
- Improve error handling
- Documentation
