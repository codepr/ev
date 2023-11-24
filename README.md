EV
==

Light event-loop library loosely inspired by the excellent libuv, in a single
**small** (< 700 sloc) header, based on the common IO multiplexing
implementations available, epoll on linux, kqueue on BSD-like and OSX,
poll/select as a fallback, dependencies-free.
A common usage of the library is to craft event-driven TCP servers, `ev_tcp.h`
exposes a set of APIs to fulfill this purpose in a simple manner.

TLS is supported as well through OpenSSL, and source have to be compiled adding
a `-DHAVE_OPENSSL=1` to enable it. Of course it requires libssl-dev installed
on the host machine to work.

In conclusion the library is composed of 2 distinct modules

- `ev.h` a generic eventloop for I/O bound concurrency on a single-thread:
    - Based on the best multiplexing IO implementation available on the host,
      supporting epoll/poll/select on linux and kqueue on BSD
    - All IO operations are done in a non-blocking way
    - Support for time based repeated tasks
- `ev_tcp.h` exposes a set of APIs to simply create an event-driven TCP server
  using `ev.h` as the main engine:
    - TCP/UNIX socket connections
    - Basic TLS support through OpenSSL
    - Callback oriented design

To adopt these libraries it's required to define a value just before inclusion
in **one** file only in the project:

```c
#define EV_SOURCE
#include "ev.h"
```

Or in case of `ev_tcp.h`

```c
#define EV_SOURCE
#define EV_TCP_SOURCE
#include "ev_tcp.h"
```

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

Lightweight event-driven hello world TCP server

```c
#include <stdio.h>
#include <stdlib.h>
#define EV_SOURCE      // add before ev_tcp
#define EV_TCP_SOURCE  // add before ev_tcp
#include "../ev_tcp.h"

#define HOST    "127.0.0.1"
#define PORT    5959
#define BACKLOG 128

static void on_close(ev_tcp_handle *client, int err) {
    (void) client;
    if (err == EV_TCP_SUCCESS)
        printf("Connection closed\n");
    else
        printf("Connection closed: %s\n", ev_tcp_err(err));
    free(client);
}

static void on_write(ev_tcp_handle *client) {
    (void) client;
    printf("Written response\n");
}

static void on_data(ev_tcp_handle *client) {
    printf("Received %li bytes\n", client->buffer.size);
    if (strncmp(client->buffer.buf, "quit", 4) == 0)
        ev_tcp_close_handle(client);
    else
        // Enqueue a write of the buffer content for the next loop cycle
        ev_tcp_enqueue_write(client);
        // If want to respond on the same loop cycle
        // ev_tcp_write(client);
}

static void on_connection(ev_tcp_handle *server) {
    ev_tcp_handle *client = malloc(sizeof(*client));
    if (!client) {
        fprintf(stderr, "On connection failed: Out of memory");
        exit(EXIT_FAILURE);
    }
    int err = ev_tcp_server_accept(server, client, on_data, on_write);
    if (err < 0)
        free(client);
    else
        ev_tcp_handle_set_on_close(client, on_close);
}

int main(void) {

    ev_context *ctx = ev_get_context();
    ev_tcp_server server;
    int err = 0;
    if ((err = ev_tcp_server_init(&server, ctx, 128)) < 0) {
        fprintf(stderr, "ev_tcp_server_init failed: %s", ev_tcp_err(err));
        exit(EXIT_FAILURE);
    }
    // To set TLS using OpenSSL
    // struct ev_tls_options tls_opt = {
    //     .ca = CA,
    //     .cert = CERT,
    //     .key = KEY
    // };
    // tls_opt.protocols = EV_TLSv1_2|EV_TLSv1_3;
    // ev_tcp_server_set_tls(&server, &tls_opt);
    int err = ev_tcp_server_listen(&server, HOST, PORT, on_connection);
    if (err < 0)
        exit(EXIT_FAILURE);
    // Blocking call
    ev_tcp_server_run(&server);
    // This could be registered to a SIGINT|SIGTERM signal notification
    // to stop the server with Ctrl+C
    ev_tcp_server_stop(&server);

    return 0;
}
```

Take a look to `examples/` directory for more snippets.

## Roadmap

- (Re)Move server abstraction on generic `ev_tcp_handle`, add client
- UDP helper APIs
- Improve error handling
- Documentation
