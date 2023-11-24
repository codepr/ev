#include <stdio.h>
#include <stdlib.h>
#define EV_SOURCE      // add before ev_tcp
#define EV_TCP_SOURCE  // add before ev_tcp
#include "../ev_tcp.h"

#define HOST         "127.0.0.1"
#define PORT         5959
#define BACKLOG      128
#define STATS_PERIOD 5

static unsigned connections = 0;
static unsigned total_connections = 0;

static void print_stats(ev_context *ctx, void *data) {
    (void) ctx;  // unused
    (void) data; // unused
    printf("Connected %u total %u\n", connections, total_connections);
}

static void on_close(ev_tcp_handle *client, int err) {
    (void) err;
    free(client);
}

static void on_data(ev_tcp_handle *client) {
    printf("Received %li bytes\n", client->buffer.size);
    if (strncmp(client->buffer.buf, "quit", 4) == 0) {
        ev_tcp_close_handle(client);
        --connections;
    } else {
        (void) ev_tcp_write(client);
    }
}

static void on_connection(ev_tcp_handle *server) {
    int err = 0;
    ev_tcp_handle *client = malloc(sizeof(*client));
    if (!client) {
        fprintf(stderr, "On connection failed: Out of memory");
        exit(EXIT_FAILURE);
    }
    if ((err = ev_tcp_server_accept(server, client, on_data, NULL)) < 0) {
        if (err == -1)
            fprintf(stderr, "Error occured: %s\n", strerror(errno));
        else
            fprintf(stderr, "Error occured: %s\n", ev_tcp_err(err));
        free(client);
    } else {
        ev_tcp_handle_set_on_close(client, on_close);
        ++connections;
        ++total_connections;
    }
}

int main(void) {

    ev_context *ctx = ev_get_context();
    ev_register_cron(ctx, print_stats, NULL, STATS_PERIOD, 0);
    ev_tcp_server server;
    int err = 0;
    if ((err = ev_tcp_server_init(&server, ctx, BACKLOG)) < 0) {
        fprintf(stderr, "ev_tcp_server_init failed: %s", ev_tcp_err(err));
        exit(EXIT_FAILURE);
    }
    err = ev_tcp_server_listen(&server, HOST, PORT, on_connection);
    if (err < 0) {
        if (err == -1)
            fprintf(stderr, "Error occured: %s\n", strerror(errno));
        else
            fprintf(stderr, "Error occured: %s\n", ev_tcp_err(err));
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s:%i\n", HOST, PORT);

    // Blocking call
    ev_tcp_server_run(&server);

    ev_tcp_server_stop(&server);

    return 0;
}
