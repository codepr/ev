#include <stdio.h>
#include <stdlib.h>
#define EV_SOURCE     // add before ev_tcp
#define EV_TCP_SOURCE // add before ev_tcp
#include "../ev.h"
#include "../ev_tcp.h"

#define HOST "127.0.0.1"
#define PORT 5959
#define BUFSIZE 256

// STDIN buffer
static unsigned char buf[BUFSIZE];

// STDIN handling callback
static void on_stdin(ev_context *, void *);

// TCP handling callback
static void on_tcp_recv(ev_tcp_handle *);
static void on_tcp_send(ev_tcp_handle *);
static void on_tcp_close(ev_tcp_handle *, int);

static void on_tcp_close(ev_tcp_handle *client, int err) {
    (void)client;
    if (err == EV_TCP_SUCCESS)
        printf("Connection closed\n");
    else
        printf("Connection closed: %s\n", ev_tcp_err(err));
}

static void on_tcp_send(ev_tcp_handle *client) {
    printf("Written %s to server\n", client->buffer.buf);
    // Re-arm TCP client for read
    (void)ev_tcp_enqueue_read(client);
}

static void on_tcp_recv(ev_tcp_handle *client) {
    printf("Response => %s (%li bytes)\n", client->buffer.buf,
           client->buffer.size);
}

static void on_stdin(ev_context *ctx, void *ptr) {
    ssize_t n = 0;
    ev_tcp_handle *handle = ptr;
    int fd = fileno(stdin);

    // Read incoming stream of bytes from user input
    n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            goto err;
    }

    // 0 bytes read means disinput by the client
    if (n == 0) {
        ev_del_fd(ctx, fd);
        return;
    }

    // Close the input and release the resource
    if (strncmp((char *)buf, "quit", 4) == 0) {
        ev_del_fd(ctx, fd);
        exit(EXIT_SUCCESS);
    }

    ev_tcp_fill_buffer(handle, buf, n);

    ev_tcp_enqueue_write(handle);

    return;

err:
    fprintf(stderr, "read(2) - error reading data: %s\n", strerror(errno));
}

int main(void) {

    ev_context *ctx = ev_get_ev_context();
    ev_tcp_handle client = {.ctx = ctx, .addr = HOST, .port = PORT};

    int err = 0;
    if ((err = ev_tcp_connect(&client, on_tcp_recv, on_tcp_send)) < 0) {
        fprintf(stderr, "ev_tcp_connect failed: %s", ev_tcp_err(err));
        exit(EXIT_FAILURE);
    }

    ev_tcp_handle_set_on_close(&client, on_tcp_close);

    err = ev_register_event(ctx, fileno(stdin), EV_READ, on_stdin, &client);
    if (err < 0) {
        fprintf(stderr, "ev_register_event failed: %s", ev_tcp_err(err));
        exit(EXIT_FAILURE);
    }
    // Blocking call
    ev_run(ctx);

    return 0;
}
