#include <stdio.h>
#define EV_SOURCE      // add before ev_tcp
#include "../ev.h"

#define PING_SECONDS 1
#define PONG_SECONDS 5

static void ping(ev_context *ctx, void *data) {
    (void) ctx;  // unused
    (void) data; // unused
    printf("Ping\n");
}

static void pong(ev_context *ctx, void *data) {
    (void) ctx;  // unused
    (void) data; // unused
    printf("Pong\n");
}

int main(void) {
    ev_context ctx;
    ev_init(&ctx, 32);
    ev_register_cron(&ctx, ping, NULL, PING_SECONDS, 0);
    ev_register_cron(&ctx, pong, NULL, PONG_SECONDS, 0);
    ev_run(&ctx);
    ev_destroy(&ctx);
    return 0;
}
