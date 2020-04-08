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
#include <sys/un.h>
#include <arpa/inet.h>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
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
 *
 * TLS is supported through OpenSSL library, to enable it the sources must be
 * compiled using an additional custom flag -DHAVE_OPENSSL=1 and -lssl -lcrypto
 * of course.
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
 * On close callback, once a connection is closed, call this routine, mainly to
 * clean out resources or something
 */
typedef void (*close_callback)(ev_tcp_handle *, int);

/*
 * Trivial abstraction on a byte buffer, just the capacity and the current
 * size are stored beside the actual buffer
 */
struct ev_buf {
    size_t size;
    size_t capacity;
    char *buf;
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
    close_callback on_close;
};

#ifdef HAVE_OPENSSL

// TLS version that can be enabled, if OpenSSL version supports them clearly
#define EV_TLSv1       0x01
#define EV_TLSv1_1     0x02
#define EV_TLSv1_2     0x04
#define EV_TLSv1_3     0x08
#define EV_TLSvAll     (EV_TLSv1 | EV_TLSv1_1 | EV_TLSv1_2 | EV_TLSv1_3)

typedef struct ev_tls_connection ev_tls_connection;

/*
 * Just a plain connection with an SSL pointer to add encryption to the accept,
 * read and write operations
 */
struct ev_tls_connection {
    ev_connection c;
    SSL *ssl;
};

/*
 * Options structure for TLS set function, carries CA, cert and key paths as
 * well as the expected supported TLS versions, specifying them by or'ing
 * EV_TLSv* values on the protocols member
 */
struct ev_tls_options {
    char *ca;
    char *cert;
    char *key;
    int protocols;
};

#endif

/*
 * General wrapper around a connection, it is comprised of a buffer, a pointer
 * to the ev_context that must be set on creation, two optionally sentinels
 * for the read/write queue and an err reporting field.
 * Two fieds are added if TLS is enabled, ssl, a flag indicating it's
 * abilitation and a pointer to an SSL_CTX to be used as the server context.
 */
struct ev_tcp_handle {
    int err;
    size_t to_read;
    size_t to_write;
    int port;
    char addr[0xFF];
#ifdef HAVE_OPENSSL
    int ssl;
    SSL_CTX *ssl_ctx;
#endif
    ev_connection *c;
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
 * `conn_callback` as a read-callback to be invoked on reading-ready event by
 * the kernel.
 */
int ev_tcp_server_listen(ev_tcp_server *, const char *, int, conn_callback);

/*
 * Bind to a path on the filesystem, creating an UNIX socket to listen on,
 * requires an on_connection callback to be defined and passed as argument or
 * it will return an error.
 * The binding socket is set to non-blocking mode and registered to the
 * ev_tcp_server context as an EV_READ event with `conn_callback` as a read
 * callback to be invoked on reading-ready events by teh kernel.
 */
int ev_tcp_server_listen_unix(ev_tcp_server *, const char *, conn_callback);

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
int ev_tcp_server_accept(ev_tcp_handle *, ev_tcp_handle *,
                         recv_callback, send_callback);

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
 * Fires an EV_WRITE event using a service private function to schedule the
 * closing of a connection
 */
int ev_tcp_enqueue_close(ev_tcp_handle *);

/*
 * Read all the incoming bytes on the connected client FD and store the to the
 * client buffer along with the total size read. Apply decryption algorithms
 * before storing the plain data on the buffer in case of TLS enabled
 */
ssize_t ev_tcp_read(ev_tcp_handle *);

/*
 * Write the content of the client buffer to the connected client FD and reset
 * the client buffer length to according to the numeber of bytes sent out.
 * Apply decryption algorithms to the plain data on the buffer just before
 * sending it out through TCP
 */
ssize_t ev_tcp_write(ev_tcp_handle *);

/*
 * Close a connection by removing the client FD from the underlying ev_context
 * and closing it, free all resources allocated
 */
void ev_tcp_close_handle(ev_tcp_handle *);

/*
 * Just a simple helper function to retrieve a text explanation of the common
 * errors returned by the helper APIs
 */
const char *ev_tcp_err(int);

/*
 * Set an on_close function to be called after the shutdown of a connection
 */
void ev_tcp_handle_set_on_close(ev_tcp_handle *, close_callback);

#ifdef HAVE_OPENSSL

/*
 * Enable TLS on a server, loading certificate authority, certificates PEM, and
 * certificate key from the filesystem, specifying their path
 */
void ev_tcp_server_set_tls(ev_tcp_server *, const struct ev_tls_options *);

#endif

#ifdef EV_TCP_SOURCE
#ifndef EV_TCP_SOURCE_ONCE
#define EV_TCP_SOURCE_ONCE

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

static void ev_on_accept(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_server *server = data;
    server->handle.c->on_conn(&server->handle);
}

static void ev_on_recv(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_handle *handle = data;
    handle->err = ev_tcp_read(handle);

    if (handle->err == EV_TCP_SUCCESS)
        goto close;

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
        handle->c->on_recv(handle);
    }

    return;

close:
    ev_tcp_enqueue_close(handle);
}

static void ev_on_send(ev_context *ctx, void *data) {
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
        handle->c->on_send(handle);
        ev_tcp_enqueue_read(handle);
    }
}

static void ev_on_close(ev_context *ctx, void *data) {
    (void) ctx;
    ev_tcp_close_handle(data);
}

static void ev_server_on_stop(ev_context *ctx, void *data) {
    (void) ctx;
    (void) data;
    ctx->stop = 1;
}

static ev_connection *ev_connection_new(int fd) {
    ev_connection *conn = malloc(sizeof(*conn));
    conn->fd = fd;
    conn->on_conn = NULL;
    conn->on_recv = NULL;
    conn->on_send = NULL;
    conn->on_close = NULL;
    return conn;
}

static int ev_accept(int sfd, struct sockaddr_in *addr) {
    int fd;
    socklen_t addrlen = sizeof(*addr);

    /* Let's accept on listening socket */
    fd = accept(sfd, (struct sockaddr *) addr, &addrlen);

    if (fd <= 0)
        goto exit;

    (void) set_nonblocking(fd);

exit:
    return fd;
}

static void ev_buf_init(ev_buf *buf, size_t capacity) {
    buf->size = 0;
    buf->capacity = capacity;
    buf->buf = calloc(buf->capacity, sizeof(unsigned char));
}

/*
 * init a fresh new tcp_handle which can be used as a server or a client
 */
static void ev_tcp_handle_init(ev_tcp_handle *handle, int fd) {
    handle->c = ev_connection_new(fd);
    ev_buf_init(&handle->buffer, EV_TCP_BUFSIZE);
    handle->to_read = handle->to_write = 0;
}

#ifdef HAVE_OPENSSL

static ev_connection *ev_tls_connection_new(int fd, SSL *ssl) {
    ev_tls_connection *conn = malloc(sizeof(*conn));
    conn->c.fd = fd;
    conn->ssl = ssl;
    conn->c.on_conn = NULL;
    conn->c.on_recv = NULL;
    conn->c.on_send = NULL;
    conn->c.on_close = NULL;
    return (ev_connection *) conn;
}

static void openssl_init() {
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void openssl_cleanup() {
    EVP_cleanup();
}

static SSL_CTX *ssl_ctx_new(int protocols) {

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    // TLS_server_method has been added with OpenSSL version > 1.1.0
    // and should be used in place of SSLv* which is goind to be deprecated
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
#else
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
#endif // OPENSSL_VERSION_NUMBER
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);

    if (!(protocols & EV_TLSv1))
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
    if (!(protocols & EV_TLSv1_1))
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
#ifdef SSL_OP_NO_TLSv1_2
    if (!(protocols & EV_TLSv1_2))
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_3
    if (!(protocols & EV_TLSv1_3))
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl_ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

    return ssl_ctx;
}

static int client_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx) {

    (void) ctx;  // Unused

	/* Preverify should check expiry, revocation. */
	return preverify_ok;
}

static void load_certificates(SSL_CTX *ctx, const char *ca,
                              const char *cert, const char *key) {

    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, client_certificate_verify);
    SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

static SSL *ssl_accept(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    ERR_clear_error();
    if (SSL_accept(ssl) <= 0)
        ERR_print_errors_fp(stderr);
    return ssl;
}

static void ev_tls_tcp_handle_init(ev_tcp_handle *handle, int fd, SSL *ssl) {
    handle->c = ev_tls_connection_new(fd, ssl);
    ev_buf_init(&handle->buffer, EV_TCP_BUFSIZE);
    handle->ssl = 1;
    handle->to_read = handle->to_write = 0;
}

#endif // HAVE_OPENSSL

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
                      EV_CLOSEFD|EV_READ, ev_server_on_stop, NULL);
#else
    pipe(server->run);
    ev_register_event(server->handle.ctx, server->run[1],
                      EV_CLOSEFD|EV_READ, ev_server_on_stop, NULL);
#endif
    server->handle.c = ev_connection_new(-1);
    return EV_OK;
}

int ev_tcp_server_listen_unix(ev_tcp_server *server, const char *socketpath,
                              conn_callback on_connection) {
    if (!on_connection)
        return EV_TCP_MISSING_CALLBACK;

    struct sockaddr_un addr;
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        goto err;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, socketpath, sizeof(addr.sun_path) - 1);
    unlink(socketpath);

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
        goto err;

    /*
     * Let's make the socket non-blocking (strongly advised to use the
     * eventloop)
     */
    (void) set_nonblocking(fd);

    /* Finally let's make it listen */
    if (listen(fd, server->backlog) != 0)
        goto err;

    server->handle.c->fd = fd;
    snprintf(server->handle.addr, strlen(socketpath), "%s", socketpath);
    server->handle.port = 0;
    server->handle.c->on_conn = on_connection;

    // Register to service callback
    ev_register_event(server->handle.ctx, server->handle.c->fd,
                      EV_READ, ev_on_accept, server);

    return EV_TCP_SUCCESS;
err:
    return EV_TCP_FAILURE;
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

        /* set SO_REUSEADDR so the socket will be reusable after process kill */
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                       &(int) { 1 }, sizeof(int)) < 0)
            goto err;

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

    server->handle.c->fd = listen_fd;
    snprintf(server->handle.addr, strlen(host), "%s", host);
    server->handle.port = port;
    server->handle.c->on_conn = on_connection;

    // Register to service callback
    ev_register_event(server->handle.ctx, server->handle.c->fd,
                      EV_READ, ev_on_accept, server);

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
    if (server->handle.c->fd > 0) {
        ev_del_fd(server->handle.ctx, server->handle.c->fd);
        close(server->handle.c->fd);
    }
    free(server->handle.c);
#ifdef HAVE_OPENSSL
    SSL_CTX_free(server->handle.ssl_ctx);
    openssl_cleanup();
#endif
#if defined(EPOLL) || defined(__linux__)
    eventfd_write(server->run, 1);
#else
    (void) write(server->run[0], &(unsigned long){1}, sizeof(unsigned long));
#endif
}

int ev_tcp_server_accept(ev_tcp_handle *server, ev_tcp_handle *client,
                         recv_callback on_data, send_callback on_send) {
    if (!on_data)
        return EV_TCP_MISSING_CALLBACK;
    while (1) {
        struct sockaddr_in addr;
        int fd = ev_accept(server->c->fd, &addr);
        if (fd < 0)
            break;
        if (fd == 0)
            continue;

        // XXX placeholder
#ifdef HAVE_OPENSSL
        if (server->ssl == 1) {
            ev_tls_tcp_handle_init(client, fd, ssl_accept(server->ssl_ctx, fd));
        } else {
#endif
            ev_tcp_handle_init(client, fd);
#ifdef HAVE_OPENSSL
        }
#endif
        inet_ntop(AF_INET, &addr.sin_addr, client->addr, sizeof(server->addr));
        client->port = ntohs(addr.sin_port);

        client->ctx = server->ctx;
        int err = ev_register_event(server->ctx, fd,
                                    EV_READ, ev_on_recv, client);
        if (err < 0)
            return EV_TCP_FAILURE;
        client->c->on_recv = on_data;
        client->c->on_send = on_send;
    }
    return EV_TCP_SUCCESS;
}

int ev_tcp_enqueue_write(ev_tcp_handle *client) {
    if (!client->c->on_send)
        return EV_TCP_MISSING_CALLBACK;
    int err = ev_fire_event(client->ctx, client->c->fd,
                            EV_WRITE, ev_on_send, client);
    if (err < 0)
        return EV_TCP_FAILURE;
    return EV_TCP_SUCCESS;
}

int ev_tcp_enqueue_read(ev_tcp_handle *client) {
    if (!client->c->on_recv)
        return EV_TCP_MISSING_CALLBACK;
    int err = ev_fire_event(client->ctx, client->c->fd,
                            EV_READ, ev_on_recv, client);
    if (err < 0)
        return EV_TCP_FAILURE;
    return EV_TCP_SUCCESS;
}

int ev_tcp_enqueue_close(ev_tcp_handle *client) {
    return ev_fire_event(client->ctx, client->c->fd, EV_WRITE, ev_on_close, client);
}

ssize_t ev_tcp_read(ev_tcp_handle *client) {
#ifdef HAVE_OPENSSL
    if (client->ssl == 1) {
        SSL *ssl = ((ev_tls_connection *) client->c)->ssl;
        ssize_t n = 0;

        ERR_clear_error();

        do {
            n = SSL_read(ssl, client->buffer.buf + client->buffer.size,
                         client->buffer.capacity - client->buffer.size);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_NONE)
                    continue;
                if (err == SSL_ERROR_ZERO_RETURN
                    || (err == SSL_ERROR_SYSCALL && !errno))
                    return EV_TCP_SUCCESS;  // Connection closed
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                else
                    goto err;
            }

            if (n == 0)
                return EV_TCP_SUCCESS;

            client->buffer.size += n;

            if (client->buffer.size == client->buffer.capacity) {
                client->buffer.capacity *= 2;
                client->buffer.buf =
                    realloc(client->buffer.buf, client->buffer.capacity);
            }
        } while (n > 0);

        return client->buffer.size;

    err:

        fprintf(stderr, "SSL_read(2) - error reading data: %s\n", strerror(errno));
        return EV_TCP_FAILURE;

    } else {
#endif
        size_t size = client->to_read > 0 ? client->to_read : client->buffer.capacity;
        ssize_t n = 0;
        /* Read incoming stream of bytes */
        do {
            n = read(client->c->fd, client->buffer.buf + client->buffer.size,
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
#ifdef HAVE_OPENSSL
    }
#endif
}

ssize_t ev_tcp_write(ev_tcp_handle *client) {
#ifdef HAVE_OPENSSL
    if (client->ssl == 1) {
        size_t total = client->buffer.size;
        ssize_t n = 0;
        SSL *ssl = ((ev_tls_connection *) client->c)->ssl;

        ERR_clear_error();

        while (client->buffer.size > 0) {
            if ((n = SSL_write(ssl, client->buffer.buf + n,
                               client->buffer.size)) <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_WRITE || SSL_ERROR_NONE)
                    continue;
                if (err == SSL_ERROR_ZERO_RETURN
                    || (err == SSL_ERROR_SYSCALL && !errno))
                    return EV_TCP_SUCCESS;  // Connection closed
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                else
                    goto err;
            }
            client->buffer.size -= n;
        }

        return total - client->buffer.size;

    err:

        fprintf(stderr, "SSL_write(2) - error sending data: %s\n", strerror(errno));
        return EV_TCP_FAILURE;

    } else {
#endif
        ssize_t n = 0, wrote = 0;

        /* Let's reply to the client */
        while (client->buffer.size > 0) {
            n = write(client->c->fd, client->buffer.buf + n, client->buffer.size);
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
#ifdef HAVE_OPENSSL
    }
#endif
}

void ev_tcp_close_handle(ev_tcp_handle *handle) {
    ev_connection *c = handle->c;
    ev_context *h_ctx = handle->ctx;
    int fd = handle->c->fd;
    char *buf = handle->buffer.buf;
#ifdef HAVE_OPENSSL
    int ssl_enabled = handle->ssl;
    SSL *ssl;
    if (ssl_enabled == 1)
        ssl = ((ev_tls_connection *) handle->c)->ssl;
#endif
    handle->err = handle->err > 0 ? EV_TCP_SUCCESS : handle->err;
    if (handle->c->on_close)
        handle->c->on_close(handle, handle->err);
#ifdef HAVE_OPENSSL
    if (ssl_enabled == 1)
        SSL_free(ssl);
#endif
    ev_del_fd(h_ctx, fd);
    close(fd);
    free(c);
    free(buf);
}

void ev_tcp_handle_set_on_close(ev_tcp_handle *h, close_callback on_close) {
    h->c->on_close = on_close;
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

#ifdef HAVE_OPENSSL

void ev_tcp_server_set_tls(ev_tcp_server *server,
                           const struct ev_tls_options *opt) {
    server->handle.ssl = 1;
    openssl_init();
    server->handle.ssl_ctx = ssl_ctx_new(opt->protocols);
    load_certificates(server->handle.ssl_ctx, opt->ca, opt->cert, opt->key);
}


#endif

#endif // EV_TCP_SOURCE_ONCE
#endif // EV_TCP_SOURCE

#endif // EV_TCP_H
