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

    ev_tcp_server server;
    ev_tcp_server_listen(&server, "127.0.0.1", 5959, on_connection);
    ev_tcp_server_stop(&server);

    return 0;
}
