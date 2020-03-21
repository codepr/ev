#include <stdio.h>
#include <stdlib.h>
#include "../ev.h"

static void on_data(ev_tcp_client *client) {
    ev_tcp_read(client);
    printf("Received %li bytes\n", client->bufsize);
    if (strncmp(client->buf, "quit", 4) == 0)
        ev_tcp_close_connection(client);
    else
        (void) ev_tcp_write(client);
}

static void on_connection(ev_tcp_server *server) {
    int err = 0;
    ev_tcp_client *client = malloc(sizeof(*client));
    if ((err = ev_tcp_server_accept(server, client, on_data)) < 0) {
        if (err < 0) {
            if (err == -1)
                fprintf(stderr, "Something went wrong %s\n", strerror(errno));
            else
                fprintf(stderr, "Something went wrong %s\n", ev_tcp_err(err));
        }
    }
}

int main(void) {

    ev_context *ctx = ev_get_ev_context();
    ev_tcp_server server;
    ev_tcp_server_init(&server, ctx, 128);
    int err = ev_tcp_server_listen(&server, "127.0.0.1", 5959, on_connection);
    if (err < 0) {
        if (err == -1)
            fprintf(stderr, "Something went wrong %s\n", strerror(errno));
        else
            fprintf(stderr, "Something went wrong %s\n", ev_tcp_err(err));
    }
    ev_tcp_server_stop(&server);

    return 0;
}
