CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic

echo-server: examples/echo_server.c ev.h
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE examples/echo_server.c -o echo_server

ping-pong: examples/ping_pong.c ev.h
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE examples/ping_pong.c -o ping_pong

ev-tcp-server: examples/ev_tcp_server.c ev.h
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE examples/ev_tcp_server.c -o ev_tcp_server

ev-tcp-server-stats: examples/ev_tcp_server_stats.c ev.h
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE examples/ev_tcp_server_stats.c -o ev_tcp_server_stats
clean:
	@rm echo_server ping_pong ev_tcp_server ev_tcp_server_stats
