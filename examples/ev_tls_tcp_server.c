#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define EV_SOURCE      // add before ev_tcp
#define EV_TCP_SOURCE  // add before ev_tcp
#include "../ev_tcp.h"

#define HOST    "127.0.0.1"
#define PORT    5959
#define BACKLOG 128
#define CA      "./certs/ca.crt"      // set me
#define CERT    "./certs/cert.crt"    // set me
#define KEY     "./certs/keyfile.key" // set me

static void on_close(ev_tcp_handle *client, int err) {
    (void) err;
    free(client);
}

static void on_data(ev_tcp_handle *client) {
    printf("Received %li bytes\n", client->buffer.size);
    if (strncmp(client->buffer.buf, "quit", 4) == 0) {
        ev_tcp_close_handle(client);
    } else {
        (void) ev_tcp_write(client);
    }
}

static void on_connection(ev_tcp_handle *server) {
    int err = 0;
    ev_tcp_handle *client = malloc(sizeof(*client));
    if ((err = ev_tcp_server_accept(server, client, on_data, NULL)) < 0) {
        if (err == -1)
            fprintf(stderr, "Something went wrong %s\n", strerror(errno));
        else
            fprintf(stderr, "Something went wrong %s\n", ev_tcp_err(err));
        free(client);
    } else {
        ev_tcp_handle_set_on_close(client, on_close);
    }
}

int main(void) {

    ev_context *ctx = ev_get_ev_context();
    ev_tcp_server server;
    struct ev_tls_options tls_opt = {
        .ca = CA,
        .cert = CERT,
        .key = KEY
    };
    tls_opt.protocols = EV_TLSvAll;
    ev_tcp_server_init(&server, ctx, BACKLOG);
    ev_tcp_server_set_tls(&server, &tls_opt);
    int err = ev_tcp_server_listen(&server, HOST, PORT, on_connection);
    if (err < 0) {
        if (err == -1)
            fprintf(stderr, "Something went wrong %s\n", strerror(errno));
        else
            fprintf(stderr, "Something went wrong %s\n", ev_tcp_err(err));
    }

    printf("Listening on %s:%i\n", HOST, PORT);

    // Blocking call
    ev_tcp_server_run(&server);

    // This could be registered to a SIGINT|SIGTERM signal notification
    // to stop the server with Ctrl+C
    ev_tcp_server_stop(&server);

    return 0;
}
