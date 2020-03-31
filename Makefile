.POSIX:
CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic -D_DEFAULT_SOURCE=200809L

echo-server: examples/echo_server.c ev.h
	$(CC) $(CFLAGS) examples/echo_server.c -o echo_server

ping-pong: examples/ping_pong.c ev.h
	$(CC) $(CFLAGS) examples/ping_pong.c -o ping_pong

ev-tcp-server: examples/ev_tcp_server.c ev.h
	$(CC) $(CFLAGS) examples/ev_tcp_server.c -o ev_tcp_server

ev-tcp-server-stats: examples/ev_tcp_server_stats.c ev.h
	$(CC) $(CFLAGS) examples/ev_tcp_server_stats.c -o ev_tcp_server_stats

ev-tls-tcp-server: examples/ev_tls_tcp_server.c ev.h
	$(CC) $(CFLAGS) -lssl -lcrypto examples/ev_tls_tcp_server.c -o ev_tls_tcp_server

ev-tcp-server-2: examples/ev_tcp_server_2.c ev_tcp.h
	$(CC) $(CFLAGS) examples/ev_tcp_server_2.c -o ev_tcp_server_2

all: echo-server ping-pong ev-tcp-server ev-tcp-server-stats ev-tls-tcp-server

clean:
	@rm echo_server ping_pong ev_tcp_server ev_tcp_server_stats ev_tls_tcp_server
