#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../ev.h"

#define HOST    "127.0.0.1"
#define PORT    5959
#define BACKLOG 128
#define CA   "./certs/ca.crt"      // set me
#define CERT "./certs/cert.crt"    // set me
#define KEY  "./certs/keyfile.key" // set me

static SSL_CTX *ssl_ctx;

static void openssl_init() {
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void openssl_cleanup() {
    EVP_cleanup();
}

static void init_ssl_ctx() {

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    // TLS_server_method has been added with OpenSSL version > 1.1.0
    // and should be used in place of SSLv* which is goind to be deprecated
    ssl_ctx = SSL_CTX_new(TLS_server_method());
#else
    ssl_ctx = SSL_CTX_new(SSLv23_method());
#endif // OPENSSL_VERSION_NUMBER
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);

    // TLSv1_2
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl_ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif
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

/*
 * Sends a stream of bytes as indicated by the size member of the stream
 * structure passed in as argument, just like the `stream_send` function but
 * using an inited SSL pointer to encrypt the data before sending it out
 */
static ssize_t ssl_send(ev_tcp_client *client) {
    size_t total = client->bufsize;
    ssize_t n = 0;
    SSL *ssl = client->ptr;

    ERR_clear_error();

    while (client->bufsize > 0) {
        if ((n = SSL_write(ssl, client->buf + n, client->bufsize)) <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || SSL_ERROR_NONE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN
                || (err == SSL_ERROR_SYSCALL && !errno))
                return 0;  // Connection closed
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }
        client->bufsize -= n;
    }

    return total - client->bufsize;

err:

    fprintf(stderr, "SSL_write(2) - error sending data: %s\n", strerror(errno));
    return -1;
}

static ssize_t ssl_recv(ev_tcp_client *client) {

    SSL *ssl = client->ptr;
    ssize_t n = 0;

    ERR_clear_error();

    do {
        n = SSL_read(ssl, client->buf + client->bufsize,
                     client->capacity - client->bufsize);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_NONE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN
                || (err == SSL_ERROR_SYSCALL && !errno))
                return 0;  // Connection closed
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                goto err;
        }

        if (n == 0)
            return 0;

        client->bufsize += n;

        if (client->bufsize == client->capacity) {
            client->capacity *= 2;
            client->buf = realloc(client->buf, client->capacity);
        }
    } while (n > 0);

    return client->bufsize;

err:

    fprintf(stderr, "SSL_read(2) - error reading data: %s\n", strerror(errno));
    return -1;
}

static void on_data(ev_tcp_client *client) {
    ssize_t n = ssl_recv(client);
    printf("Received %li bytes\n", n);
    if (strncmp(client->buf, "quit", 4) == 0 || n == 0) {
        ev_tcp_close_connection(client);
    } else {
        n = ssl_send(client);
        if (n == -1) {
            goto err;
        } else {
            if (ev_tcp_server_enqueue_read(client) < 0)
                goto err;
        }
    }
err:
    fprintf(stderr, "Something went wrong on_data");
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

    client->ptr = (SSL *) ssl_accept(ssl_ctx, client->fd);
}

int main(void) {

    ev_context *ctx = ev_get_ev_context();
    openssl_init();
    init_ssl_ctx();
    load_certificates(ssl_ctx, CA, CERT, KEY);
    ev_tcp_server server;
    ev_tcp_server_init(&server, ctx, BACKLOG);
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

    SSL_CTX_free(ssl_ctx);
    openssl_cleanup();

    return 0;
}
