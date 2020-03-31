/* BSD 2-Clause License
 *
 * Copyright (c) 2020, Andrea Giacomo Baldan All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef EV_TCP_H
#define EV_TCP_H

#include <netdb.h>
#include <fcntl.h>
#include "ev.h"

/*
 * =================================
 *  TCP server helper APIs exposed
 * =================================
 *
 * A set of basic helpers to create a lightweight event-driven TCP server based
 * on non-blocking sockets and IO multiplexing using ev as underlying
 * event-loop.
 *
 * As of now it's stll very simple, the only tweakable value is the buffer
 * memory size for incoming and to-be-written stream of bytes for clients, the
 * default value is 2048.
 *
 * #define EV_TCP_BUFSIZE 2048
 */

#define EV_TCP_SUCCESS           0
#define EV_TCP_FAILURE          -1
#define EV_TCP_MISSING_CALLBACK -2
#define EV_TCP_MISSING_CONTEXT  -3

/*
 * Default buffer size for connecting client, can be changed on the host
 * application
 */
#define EV_TCP_BUFSIZE           2048

typedef struct ev_buf ev_buf;
typedef struct ev_connection ev_connection;
typedef struct ev_tcp_server ev_tcp_server;
typedef struct ev_tcp_handle ev_tcp_handle;

/*
 * Core actions of a ev_tcp_handle, callbacks to be executed at each of these
 * events happening
 */

/*
 * On new connection callback, defines the behaviour of the application when a
 * new client connects
 */
typedef void (*conn_callback)(ev_tcp_handle *);

/*
 * On data incoming from an already connected client callback, defines what the
 * application must do with the stream of bytes received by a connected client
 */
typedef void (*recv_callback)(ev_tcp_handle *);

/*
 * On write callback, once the application receives and process a bunch of
 * bytes, this defines what and how to do with the response to be sent out
 */
typedef void (*send_callback)(ev_tcp_handle *);

/*
 * Trivial abstraction on a byte buffer, just the capacity and the current
 * size are stored beside the actual buffer
 */
struct ev_buf {
    size_t size;
    size_t capacity;
    unsigned char *buf;
};

/*
 * Connection abstraction, as of now it's pretty self-explanatory, it is
 * composed of the file descriptor for socket and 3 main callbacks:
 *
 * - on_connection: Will be triggered when a client contact the server just
 *                  before accepting a connection
 * - on_recv:       Generally set inside on_connection callback, define how to
 *                  react to incoming data from an alredy connected client
 * - on_send:       Optionally used as responses can be sent directly from
 *                  on_recv callback through `ev_tcp_write` call, define the
 *                  behaviour of the server on response to clients
 */
struct ev_connection {
    int fd;
    conn_callback on_conn;
    recv_callback on_recv;
    send_callback on_send;
};

/*
 * General wrapper around a connection, it is comprised of a buffer, a pointer
 * to the ev_context that must be set on creation, two optionally sentinels
 * for the read/write queue and an err reporting field.
 */
struct ev_tcp_handle {
    int err;
    size_t to_read;
    size_t to_write;
    ev_connection c;
    ev_buf buffer;
    ev_context *ctx;
};

/*
 * Server abstraction, beside the handle storing the listening socket and
 * optionally some callbacks, it is composed of the backlog to be set on listen
 * system call, a running switch to be used to stop the server, host and port
 * to listen on.
 */
struct ev_tcp_server {
    ev_tcp_handle handle;
#if defined(__linux__)
    int run;
#else
    int run[2];
#endif
    int backlog;
    int port;
    char host[0xff];
};

/*
 * Sets the tcp backlog and the ev_context reference to an ev_tcp_server,
 * setting to NULL the 3 main actions callbacks.
 * The ev_context have to be alredy initialized or it returns an error.
 * Up to the caller to decide how to create the ev_tcp_server and thus manage,
 * its ownership and memory lifetime by allocating it on the heap or the
 * stack
 */
int ev_tcp_server_init(ev_tcp_server *, ev_context *, int);

/*
 * Make the tcp server in listening mode, requires an on_connection callback to
 * be defined and passed as argument or it will return an error.
 * Under the hood the listening socket created is set to non-blocking mode and
 * registered to the ev_tcp_server context as an EV_READ event with
 * `conn_callback` as a read-callback to be called on reading-ready event by
 * the kernel.
 */
int ev_tcp_server_listen(ev_tcp_server *, const char *, int, conn_callback);

/*
 * Start the tcp server, it's a blocking call that calls ev_run on the
 * underlyng ev_context
 */
void ev_tcp_server_run(ev_tcp_server *);

/*
 * Stops a listening ev_tcp_server by removing it's listening socket from the
 * underlying running loop and closing it, finally it stops the underlying
 * eventloop
 */
void ev_tcp_server_stop(ev_tcp_server *);

/*
 * Accept the connection, requires a pointer to ev_tcp_client and a on_recv
 * callback, othersiwse it will return an err. Up to the user to manage the
 * ownership of the client, tough generally it's advisable to allocate it on
 * the heap to being able to juggle it around other callbacks
 */
int ev_tcp_server_accept(ev_tcp_handle *, ev_tcp_handle *, recv_callback);

/*
 * Fires an EV_READ event using a service private function to just read the
 * incoming stream of data from a client into the buffer, return an error if no
 * on_recv callback was set, see `ev_tcp_server_set_on_recv`
 */
int ev_tcp_enqueue_read(ev_tcp_handle *);

/*
 * Fires a EV_WRITE event using a service private function to just write the
 * content of the buffer to the client, return an error if no on_send callback
 * was set, see `ev_tcp_server_set_on_send`
 */
int ev_tcp_enqueue_write(ev_tcp_handle *);

/*
 * Read all the incoming bytes on the connected client FD and store the to the
 * client buffer along with the total size read.
 */
ssize_t ev_tcp_read(ev_tcp_handle *);

/*
 * Write the content of the client buffer to the connected client FD and reset
 * the client buffer length to according to the numeber of bytes sent out.
 */
ssize_t ev_tcp_write(ev_tcp_handle *);

/*
 * Close a connection by removing the client FD from the underlying ev_context
 * and closing it, free all resources allocated
 */
void ev_tcp_close_connection(ev_tcp_handle *);

/*
 * Just a simple helper function to retrieve a text explanation of the common
 * errors returned by the helper APIs
 */
const char *ev_tcp_err(int);

/* Set non-blocking socket */
static inline int set_nonblocking(int fd) {
    int flags, result;
    flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        goto err;

    result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (result == -1)
        goto err;

    return EV_OK;

err:

    fprintf(stderr, "set_nonblocking: %s\n", strerror(errno));
    return EV_ERR;
}

/*
 * ===================================================================
 *  Service private callbacks, acts as a bridge for scheudling server
 *  callbacks
 * ===================================================================
 */

static void on_accept(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_server *server = data;
    server->handle.c.on_conn(&server->handle);
}

static void on_recv(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_handle *handle = data;
    handle->err = ev_tcp_read(handle);

    if (handle->err == EV_TCP_SUCCESS)
        ev_tcp_close_connection(handle);

    /*
     * If EAGAIN happened and there still more data to read, re-arm
     * for a read on the next loop cycle, hopefully the kernel will be
     * available to send remaining data
     */
    if (handle->to_read > 0 && handle->buffer.size < handle->to_read
        && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        handle->to_read -= handle->buffer.size;
        ev_tcp_enqueue_read(handle);
    } else {
        handle->c.on_recv(handle);
    }
}

static void on_send(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_handle *handle = data;
    handle->err = ev_tcp_write(handle);
    /*
     * If EAGAIN happened and there still more data to be written out, re-arm
     * for a write on the next loop cycle, hopefully the kernel will be
     * available to send remaining data
     */
    if (handle->buffer.size > 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        ev_tcp_enqueue_write(handle);
    } else {
        handle->c.on_send(handle);
    }
}

static void on_stop(ev_context *ctx, void *data) {
    (void) ctx;
    (void) data;
    ctx->stop = 1;
}

/*
 * =================
 *  APIs definition
 * =================
 */

int ev_tcp_server_init(ev_tcp_server *server, ev_context *ctx, int backlog) {
    if (!ctx)
        return EV_TCP_MISSING_CONTEXT;
    server->backlog = backlog;
    // TODO check for context running
    server->handle.ctx = ctx;
#if defined(EPOLL) || defined(__linux__)
    server->run = eventfd(0, EFD_NONBLOCK);
    ev_register_event(server->handle.ctx, server->run,
                      EV_CLOSEFD|EV_READ, on_stop, NULL);
#else
    pipe(server->run);
    ev_register_event(server->handle.ctx, server->run[1],
                      EV_CLOSEFD|EV_READ, on_stop, NULL);
#endif
    server->handle.c.on_conn = NULL;
    server->handle.c.on_recv = NULL;
    server->handle.c.on_send = NULL;
    return EV_OK;
}

int ev_tcp_server_listen(ev_tcp_server *server, const char *host,
                         int port, conn_callback on_connection) {

    if (!on_connection)
        return EV_TCP_MISSING_CALLBACK;

    int listen_fd = -1;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };
    struct addrinfo *result, *rp;
    char port_str[6];

    snprintf(port_str, 6, "%i", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0)
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
    (void) set_nonblocking(listen_fd);

    /* Finally let's make it listen */
    if (listen(listen_fd, server->backlog) != 0)
        goto err;

    server->handle.c.fd = listen_fd;
    snprintf(server->host, strlen(host), "%s", host);
    server->port = port;
    server->handle.c.on_conn = on_connection;

    // Register to service callback
    ev_register_event(server->handle.ctx, server->handle.c.fd,
                      EV_READ, on_accept, server);

    return EV_TCP_SUCCESS;
err:
    return EV_TCP_FAILURE;
}

void ev_tcp_server_run(ev_tcp_server *server) {
    if (ev_is_running(server->handle.ctx) == 1)
        return;
    // Blocking call
    ev_run(server->handle.ctx);
}

void ev_tcp_server_stop(ev_tcp_server *server) {
    ev_del_fd(server->handle.ctx, server->handle.c.fd);
    close(server->handle.c.fd);
#if defined(EPOLL) || defined(__linux__)
    eventfd_write(server->run, 1);
#else
    (void) write(server->run[0], &(unsigned long){1}, sizeof(unsigned long));
#endif
}

void ev_buf_init(ev_buf *buf, size_t capacity) {
    buf->size = 0;
    buf->capacity = capacity;
    buf->buf = calloc(buf->capacity, sizeof(unsigned char));
}

int ev_tcp_server_accept(ev_tcp_handle *server,
                         ev_tcp_handle *client, recv_callback on_data) {
    if (!on_data)
        return EV_TCP_MISSING_CALLBACK;
    client->c.on_recv = on_data;
    while (1) {
        int fd;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        /* Let's accept on listening socket */
        if ((fd = accept(server->c.fd, (struct sockaddr *) &addr, &addrlen)) < 0)
            break;

        if (fd == 0)
            continue;

        /* Make the new accepted socket non-blocking */
        (void) set_nonblocking(fd);

        // XXX placeholder
        client->c.fd = fd;
        client->ctx = server->ctx;
        ev_buf_init(&client->buffer, EV_TCP_BUFSIZE);

        int err = ev_register_event(server->ctx, fd, EV_READ, on_recv, client);
        if (err < 0)
            return EV_TCP_FAILURE;
    }
    return EV_TCP_SUCCESS;
}

int ev_tcp_enqueue_write(ev_tcp_handle *client) {
    if (!client->c.on_send)
        return EV_TCP_MISSING_CALLBACK;
    int err = ev_fire_event(client->ctx, client->c.fd,
                            EV_WRITE, on_send, client);
    if (err < 0)
        return EV_TCP_FAILURE;
    return EV_TCP_SUCCESS;
}

int ev_tcp_enqueue_read(ev_tcp_handle *client) {
    if (!client->c.on_recv)
        return EV_TCP_MISSING_CALLBACK;
    int err = ev_fire_event(client->ctx, client->c.fd,
                            EV_READ, on_recv, client);
    if (err < 0)
        return EV_TCP_FAILURE;
    return EV_TCP_SUCCESS;
}

ssize_t ev_tcp_read(ev_tcp_handle *client) {
    size_t size = client->to_read > 0 ? client->to_read : client->buffer.capacity;
    ssize_t n = 0;
    /* Read incoming stream of bytes */
    do {
        n = read(client->c.fd, client->buffer.buf + client->buffer.size,
                 size - client->buffer.size);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                return n;
        }
        client->buffer.size += n;
        /* Re-size the buffer in case of overflow of bytes */
        if (client->buffer.size == client->buffer.capacity) {
            client->buffer.capacity *= 2;
            client->buffer.buf =
                realloc(client->buffer.buf, client->buffer.capacity);
        }
    } while (n > 0);

    /* 0 bytes read means disconnection by the client */
    if (n == 0)
        return 0;

    return client->buffer.size;
}

ssize_t ev_tcp_write(ev_tcp_handle *client) {
    ssize_t n = 0, wrote = 0;

    /* Let's reply to the client */
    while (client->buffer.size > 0) {
        n = write(client->c.fd, client->buffer.buf + n, client->buffer.size);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                return n;
        }
        client->buffer.size -= n;
        wrote += n;
    }

    return wrote;
}

void ev_tcp_close_connection(ev_tcp_handle *client) {
    ev_del_fd(client->ctx, client->c.fd);
    close(client->c.fd);
    free(client->buffer.buf);
    free(client);
}

const char *ev_tcp_err(int rc) {
    switch (rc) {
        case EV_TCP_SUCCESS:
            return "Success";
        case EV_TCP_FAILURE:
            return "Failure";
        case EV_TCP_MISSING_CALLBACK:
            return "Missing callback";
        default:
            return "Unknown error";
    }
}

#endif
