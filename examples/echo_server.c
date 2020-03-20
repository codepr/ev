#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../ev.h"

/*
 * Simple echo server using ev's APIs, will listen on 127.0.0.1:5000, endpoint
 * can be changed modifying HOST and PORT defines.
 *
 * Can be tested with netcat or telnet:
 * $ telnet localhost 5000
 */

#define HOST "127.0.0.1"
#define PORT 5000
#define BUFSIZE 1024

static void on_connection(ev_context *, void *);
static void on_data(ev_context *, void *);
static void on_response(ev_context *, void *);

struct connection {
    int fd;
    size_t bufsize;
    size_t capacity;
    unsigned char *buf;
};

/* Set non-blocking socket */
static inline int set_nonblocking(int fd) {
    int flags, result;
    flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        goto err;

    result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (result == -1)
        goto err;

    return 0;

err:

    fprintf(stderr, "set_nonblocking: %s\n", strerror(errno));
    return -1;
}

static int connection_init(struct connection *conn, int fd) {
    if (!conn)
        return -1;
    conn->fd = fd;
    conn->bufsize = 0;
    conn->capacity = BUFSIZE;
    conn->buf = calloc(1, BUFSIZE);
    return 0;
}

static void connection_close(struct connection *conn) {
    if (!conn)
        return;
    close(conn->fd);
    free(conn->buf);
    free(conn);
}

static void on_connection(ev_context *ctx, void *data) {
    int listen_fd = *(int *) data;
    while (1) {
        int fd;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        /* Let's accept on listening socket */
        if ((fd = accept(listen_fd, (struct sockaddr *) &addr, &addrlen)) < 0)
            break;

        if (fd == 0)
            continue;

        /* Make the new accepted socket non-blocking */
        (void) set_nonblocking(fd);

        struct connection *conn = malloc(sizeof(*conn));
        if (connection_init(conn, fd) == -1)
            exit(EXIT_FAILURE);

        /* Register the new connected client to the read data callback */
        ev_register_event(ctx, fd, EV_READ, on_data, conn);
    }
}

static void on_data(ev_context *ctx, void *data) {
    ssize_t n = 0;
    struct connection *conn = data;
    /* Read incoming stream of bytes */
    do {
        n = read(conn->fd, conn->buf + conn->bufsize,
                 conn->capacity - conn->bufsize);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }
        conn->bufsize += n;
        /* Re-size the buffer in case of overflow of bytes */
        if (conn->bufsize == conn->capacity) {
            conn->capacity *= 2;
            conn->buf = realloc(conn->buf, conn->capacity);
        }
    } while (n > 0);

    /* 0 bytes read means disconnection by the client */
    if (n == 0) {
        ev_del_fd(ctx, conn->fd);
        connection_close(conn);
        return;
    }

    /* Close the connection and release the resource */
    if (strncmp((char *) conn->buf, "quit", 4) == 0) {
        printf("Closing connection\n");
        ev_del_fd(ctx, conn->fd);
        connection_close(conn);
        return;
    }

    printf("Received %lu bytes\n", conn->bufsize);

    /* Fire an event to schedule a response */
    ev_fire_event(ctx, conn->fd, EV_WRITE, on_response, conn);

    return;

err:
    fprintf(stderr, "read(2) - error reading data: %s\n", strerror(errno));

}

static void on_response(ev_context *ctx, void *data) {
    struct connection *conn = data;
    ssize_t n = 0;

    /* Let's reply to the client */
    while (conn->bufsize > 0) {
        n = write(conn->fd, conn->buf + n, conn->bufsize);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }
        conn->bufsize -= n;
    }

    /* Re-arm for read */
    ev_fire_event(ctx, conn->fd, EV_READ, on_data, conn);

    return;

err:

    fprintf(stderr, "write(2) - error sending data: %s\n", strerror(errno));
}

int main(void) {

    ev_context ctx;
    int listen_fd = -1;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };
    struct addrinfo *result, *rp;
    char port[6];

    snprintf(port, 6, "%i", PORT);

    if (getaddrinfo(HOST, port, &hints, &result) != 0)
        goto err;

    /* Create a listening socket */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd < 0) continue;
        /* Bind it to the addr:port opened on the network interface */
        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break; // Succesful bind
        close(listen_fd);
    }

    freeaddrinfo(result);
    if (rp == NULL)
        goto err;

    /*
     * Let's make the socket non-blocking (strongly advised to use the
     * eventloop)
     */
    if (set_nonblocking(listen_fd) != 0)
        goto err;

    /* Finally let's make it listen */
    if (listen(listen_fd, 32) != 0)
        goto err;

    ev_init(&ctx, 32);

    /* Register a callback on the listening socket for incoming connections */
    ev_register_event(&ctx, listen_fd, EV_READ, on_connection, &listen_fd);

    printf("Listening on %s:%i\n", HOST, PORT);

    /* Start the loop */
    ev_run(&ctx);

    /* Release resources after the loop has been stopped */
    ev_destroy(&ctx);

    return 0;

err:
    fprintf(stderr, "Error occured: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}
