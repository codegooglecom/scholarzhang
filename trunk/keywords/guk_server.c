#include "guk_common.h"
#include "gfwkeyword.h"
#include <stdlib.h>
#include <errno.h>
#include <sys/select.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <signal.h>

char device[100], ip[100];
char config_file[1000] = "/etc/gfwkeyword.conf";
char candlist[1000];
struct port_range *cand;
int cand_count;
int maxconn, maxdst, time_interval, expire_timeout, tcp_mss, pps;
char times;
double kps;
struct dstlist *dest;

int listenfd;
struct sockaddr_un svname;
socklen_t sv_addrlen;
int tcp_nodelay = 1;
int running = 1;

#define DEFAULT_CLIENT 200
int max_client = DEFAULT_CLIENT;
struct pollfd *fd_all, *fd_cli;
struct sockaddr_un cli_addr;
int *cli_no;
int *cli_idx_of;
int *avai_no, avai_cnt;

struct inbuf_t {
	int len;
	char buf[GUK_MAX_QUERY_LEN];
} *in_buffer;

#define OUTBUFFER_SIZE 400
struct outbuf_t {
	int head, tail, tot;
	char buf[OUTBUFFER_SIZE];
} *out_buffer;

#define DEFAULT_QUERY 2000;
int max_query = DEFAULT_QUERY;

struct wait_item {
	int cli, seq, len;
	int cli_prev, cli_next;
	char type;
	int prev, next;
	char *url;
/* prev and next indicate the waiting queue.
 *
 * pop remove the item from the waiting queue and set url = NULL and
 * hold its place in the pending ``in'' list of the client cli (in
 * case of the close()ing of cli). when result is available, delete
 * the wait item from the list and add it to the result list depending
 * on cli.
 *
 * if it's in the testing progress, url == NULL. if cli < 0, the
 * result must be discard.
 *
 * when deleting a testing item, set cli = -1 and hold its place in
 * the list; else remove it from the waiting queue and the list then
 * free(url).
 */
};
struct wait_t {
	int head, tail;
	int avai;
	struct wait_item *item;
} waiting;
struct res_item {
	int next, seq;
	char result;
};
struct res_t {
	int avai;
	struct res_item *item;
} result;

struct pending_t {
	int in;
	int out;
	int out_tail;
/* in is just a list, out is a queue */
} *pending;

int cli_cnt;
int pcap_fd;

#define HH_ADD_LEN 24
#define HH_PRE_LEN 11
#define HH_PST_LEN 13

int allocate_mem() {
	fd_all = malloc( (max_client + 2) * sizeof(struct pollfd) );
	if (fd_all == NULL)
		goto error;
	fd_cli = fd_all + 2;
	cli_idx_of = malloc( max_client * sizeof(int));
	if (cli_idx_of == NULL)
		goto error;
	cli_no = malloc( max_client * sizeof(int) );
	if (cli_no == NULL)
		goto error;
	avai_no = malloc( max_client * sizeof(int) );
	if (avai_no == NULL)
		goto error;
	in_buffer = malloc( max_client * sizeof(struct inbuf_t) );
	if (in_buffer == NULL)
		goto error;
	out_buffer = malloc( max_client * sizeof(struct outbuf_t) );
	if (out_buffer == NULL)
		goto error;
	pending = malloc( max_client * sizeof(struct pending_t) );
	if (pending == NULL)
		goto error;

	waiting.item = malloc( max_query * sizeof(struct wait_item) );
	if (waiting.item == NULL)
		goto error;
	result.item = malloc( max_query * sizeof(struct res_item) );
	if (result.item == NULL)
		goto error;
	return 0;

error:
	perror("allocate_mem");
	return -1;
}

void free_mem() {
	if (fd_all)
		free(fd_all);
	if (cli_idx_of)
		free(cli_idx_of);
	if (avai_no)
		free(avai_no);
	if (in_buffer)
		free(in_buffer);
	if (out_buffer)
		free(out_buffer);
	if (pending)
		free(pending);

	if (waiting.item)
		free(waiting.item);
	if (result.item)
		free(result.item);
}

void inthandler (int _) {
	(void)_;
	running = 0;
}

static inline void delete_result(int item) {
	result.item[item].next = result.avai;
	result.avai = item;
}

static inline void delete_wait(int item) {
	static int prev, next;

	if (waiting.item[item].url) {
		prev = waiting.item[item].prev;
		next = waiting.item[item].next;
		if (prev >= 0)
			waiting.item[prev].next = next;
		else
			waiting.head = next;
		if (next >= 0)
			waiting.item[next].prev = prev;

		waiting.item[item].next = waiting.avai;
		waiting.avai = item;

		free(waiting.item[item].url);
	}
	else
		waiting.item[item].cli = -1;
}

static inline void close_client(int cli_idx) {
	int cli_fd, cli;
	int p;

	fprintf(stderr, "Error on client %d, close.\n", cli_no[cli_idx]);
	cli_fd = fd_cli[cli_idx].fd;
	close(cli_fd);

	cli = cli_no[cli_idx];
	in_buffer[cli].len = 0;
	out_buffer[cli].head = 0;
	out_buffer[cli].tail = 0;
	out_buffer[cli].tot = 0;
	while (pending[cli].in >= 0) {
		p = pending[cli].in;
		pending[cli].in = waiting.item[p].cli_next;
		delete_wait(p);
	}
	while (pending[cli].out >= 0) {
		p = pending[cli].out;
		pending[cli].out = result.item[p].next;
		delete_result(p);
	}
	avai_no[avai_cnt++] = cli;

	--cli_cnt;
	if (cli_idx < cli_cnt) {
		memcpy(fd_cli + cli_idx, fd_cli + cli_cnt, sizeof(struct pollfd));
		cli_idx_of[(cli_no[cli_idx] = cli_no[cli_cnt])] = cli_idx;
	}
}

static inline int accept_client() {
	static int cli_fd, cli;
	static socklen_t addrlen;

	addrlen = sizeof(struct sockaddr_un);
	cli_fd = accept(listenfd, (struct sockaddr *)(&cli_addr), &addrlen);
	if (cli_fd == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
		perror("accept");
	if (cli_fd > 0) {
		if (fcntl(cli_fd, F_SETFL, O_NONBLOCK) < 0) {
			perror("fcntl");
			close(cli_fd);
		}
		else {
			setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int));
			fd_cli[cli_cnt].fd = cli_fd;
			fd_cli[cli_cnt].events = POLLIN;
			cli_no[cli_cnt] = cli = avai_no[--avai_cnt];
			cli_idx_of[cli] = cli_cnt;
			if (cli_addr.sun_path[0] != '\0')
				fprintf(stderr, "Accept connection from unix:%s, client %d.\n",
					cli_addr.sun_path, cli_no[cli_cnt]);
			else
				fprintf(stderr, "Accept connection from abstract:%s, client %d.\n",
					cli_addr.sun_path + 1, cli_no[cli_cnt]);

			/* this was done at the beginning and at
			 * client close_client()ing. */
			//in_buffer[cli].len = 0;
			//out_buffer[cli].head = 0;
			//out_buffer[cli].tail = 0;
			//out_buffer[cli].tot = 0;
			//pending[cli].in = -1;
			//pending[cli].out = -1;

			++cli_cnt;
			return 0;
		}
	}
	return -1;
}

static inline void fputcs(FILE *stream, char *s, int count) {
	/* count <= GUK_MAX_URL_LEN */
	static char format[] = "%.9999s";
	sprintf(format, "%%.%ds", count);
	fprintf(stream, format, s);
}

static inline void pop_result(int cli) {
	static int res_idx;
	static int cnt, spc;
	static char rslt[GUK_RESULT_ITEM_SIZE + 1];

	for (res_idx = pending[cli].out; res_idx >= 0; res_idx = result.item[res_idx].next) {
		cnt = sprintf(rslt, "%d %d\n", result.item[res_idx].seq, result.item[res_idx].result);
		if (out_buffer[cli].tot + cnt <= OUTBUFFER_SIZE) {
			spc = (OUTBUFFER_SIZE - out_buffer[cli].tail);
			if (spc > cnt)
				spc = cnt;
			memcpy(out_buffer[cli].buf + out_buffer[cli].tail, rslt, spc);
			if (spc < cnt) {
				memcpy(out_buffer[cli].buf, rslt + spc, cnt - spc);
				out_buffer[cli].tail = cnt - spc;
			}
			else
				out_buffer[cli].tail += cnt;
			out_buffer[cli].tot += cnt;
		}
		else
			break;
	}
	pending[cli].out = res_idx;
}

static inline char try_read(int cli) {
	static int cnt;
	static int ret;
	static int fd;

	fd = fd_cli[cli_idx_of[cli]].fd;
	ret = 0;
	while (1) {
		cnt = GUK_MAX_QUERY_LEN - in_buffer[cli].len;
		cnt = read(fd, in_buffer[cli].buf + in_buffer[cli].len, cnt);
		if (cnt > 0) {
			if ((in_buffer[cli].len += cnt) == GUK_MAX_QUERY_LEN)
				if (NULL == memchr(in_buffer[cli].buf, '\n', GUK_MAX_QUERY_LEN)) {
					// wrong format or too long, ignore it!
					in_buffer[cli].buf[0] = 'F';
					in_buffer[cli].len = 1;
				}
			ret = 1;
		}
		else
			break;
	}
	return ret;
}

static inline char try_write(int cli) {
	static int cnt;
	static int ret;
	static int fd;

	fd = fd_cli[cli_idx_of[cli]].fd;
	ret = 0;
	while (1) {
		cnt = out_buffer[cli].head;
		if (cnt + out_buffer[cli].tot > OUTBUFFER_SIZE)
			cnt = OUTBUFFER_SIZE - cnt;
		else
			cnt = out_buffer[cli].tot;
		if (cnt == 0) {
			fd_cli[cli_idx_of[cli]].events &= ~POLLOUT;
			break;
		}
		cnt = write(fd, out_buffer[cli].buf + out_buffer[cli].head, cnt);
		if (cnt > 0) {
			out_buffer[cli].tot -= cnt;
			if ((out_buffer[cli].head += cnt) == OUTBUFFER_SIZE)
				out_buffer[cli].head = 0;
			ret = 1;
		}
		else
			break;
	}
	return ret;
}

void push_result(char *content, char rslt, void *arg) {
	static int cli, res_idx, wait_idx;
	static struct wait_item *w;

	w = arg;
	cli = w->cli;

	fprintf(stderr, "query type%d ", w->type);
	fputcs(stderr, content + HH_PRE_LEN, w->len - HH_ADD_LEN + ((w->type == 1)?2:0));
	fprintf(stderr, " result %d asked by client %d with seq %d\n", rslt & w->type, cli, w->seq);

	free(content);
	if (cli < 0)
		return;

	res_idx = result.avai;
	result.avai = result.item[res_idx].next;

	result.item[res_idx].result = rslt & w->type;
	result.item[res_idx].seq = w->seq;
	result.item[res_idx].next = -1;

	if (pending[cli].out < 0)
		pending[cli].out = res_idx;
	else
		result.item[pending[cli].out_tail].next = res_idx;
	pending[cli].out_tail = res_idx;

	w->next = waiting.avai;
	waiting.avai = wait_idx = w - waiting.item;

	if (w->cli_prev < 0)
		pending[cli].in = w->cli_next;
	else
		waiting.item[w->cli_prev].cli_next = w->cli_next;
	if (w->cli_next >= 0)
		waiting.item[w->cli_next].cli_prev = w->cli_prev;

	fd_cli[cli_idx_of[cli]].events |= POLLOUT;
}

static inline void pop_waiting() {
	static int p;
	static struct wait_item *w;
	for (p = waiting.head; p >= 0; p = w->next) {
		w = waiting.item + p;
		if (gk_add_context(w->url, w->len, NULL, w->type, push_result, w) == 0)
			w->url = NULL;
		else
			break;
	}
	waiting.head = p;
	if (p >= 0)
		w->prev = -1;
}

static inline void push_waiting(int cli) {
	static int len;
	static char *eos, *pos;
	static int wait_idx;

	while (1) {
		eos = (char *)memchr(in_buffer[cli].buf, '\n', in_buffer[cli].len);
		if (eos == NULL)
			return;
		*eos = '\0';

		wait_idx = waiting.avai;
		waiting.avai = waiting.item[wait_idx].next;

		waiting.item[wait_idx].cli = cli;
		errno = 0;
		waiting.item[wait_idx].seq = strtol(in_buffer[cli].buf, &pos, 10);
		if (errno == ERANGE || *pos != ' ')
			goto ignore;
		++pos;
		waiting.item[wait_idx].type = *pos - '0';
		++pos;
		if (*pos != ' ')
			goto ignore;
		++pos;

		/* it's at least a testing url now */
		waiting.item[wait_idx].cli_prev = -1;
		waiting.item[wait_idx].cli_next = pending[cli].in;
		if (pending[cli].in >= 0)
			waiting.item[pending[cli].in].cli_prev = wait_idx;
		pending[cli].in = wait_idx;

		len = eos - pos;
		if (waiting.item[wait_idx].type == HK_TYPE1) {
			if ((waiting.item[wait_idx].url = malloc(len + HH_ADD_LEN - 2)) == NULL)
				goto error;
			eos = waiting.item[wait_idx].url;
			memcpy(eos, "GET http://", HH_PRE_LEN);
			eos += HH_PRE_LEN;
			memcpy(eos, pos, len);
			eos += len;
			memcpy(eos, " HTTP/1.1\n\n", HH_PST_LEN - 2);
			waiting.item[wait_idx].len = len + HH_ADD_LEN - 2;
		}
		else {
			if ((waiting.item[wait_idx].url = malloc(len + HH_ADD_LEN)) == NULL)
				goto error;
			eos = waiting.item[wait_idx].url;
			memcpy(eos, "GET http://", HH_PRE_LEN);
			eos += HH_PRE_LEN;
			memcpy(eos, pos, len);
			eos += len;
			memcpy(eos, " HTTP/1.1\r\n\r\n", HH_PST_LEN);
			waiting.item[wait_idx].len = len + HH_ADD_LEN;
		}

		pos += len + 1;
		in_buffer[cli].len = in_buffer[cli].len - (pos - in_buffer[cli].buf);
		memmove(in_buffer[cli].buf, pos, in_buffer[cli].len);

		/* it's a waiting for test url now */
		waiting.item[wait_idx].next = -1;
		if (waiting.head < 0) {
			waiting.head = wait_idx;
			waiting.item[wait_idx].prev = -1;
		}
		else {
			waiting.item[waiting.tail].next = wait_idx;
			waiting.item[wait_idx].prev = waiting.tail;
		}
		waiting.tail = wait_idx;
		continue;

	ignore:
		waiting.item[wait_idx].next = waiting.avai;
		waiting.avai = wait_idx;
		continue;

	error:
		/* report the format error result */
		push_result(NULL, GUK_QUERY_FORMAT_ERROR, waiting.item + wait_idx);
		continue;
	}
}

void run() {
	long time, delta;
	int ret, cli_idx, cli;
	nfds_t nfds;

	if (allocate_mem() < 0) {
		free_mem();
		return;
	}

	cli_cnt = 0;

	nfds = 2;
	fd_all[0].fd = pcap_fd;
	fd_all[0].events = POLLIN;
	fd_all[1].fd = listenfd;
	fd_all[1].events = POLLIN;

	for (cli = 0; cli < max_client; ++cli)
		avai_no[cli] = cli;
	avai_cnt = max_client;

	result.item[max_query - 1].next = -1;
	for (ret = max_query - 2; ret >= 0; --ret)
		result.item[ret].next = ret + 1;
	result.avai = 0;

	waiting.item[max_query - 1].next = -1;
	for (ret = max_query - 2; ret >= 0; --ret)
		waiting.item[ret].next = ret + 1;
	waiting.avai = 0;
	waiting.head = -1;

	for (cli = 0; cli < max_client; ++cli) {
		in_buffer[cli].len = 0;
		out_buffer[cli].head = 0;
		out_buffer[cli].tail = 0;
		out_buffer[cli].tot = 0;
		pending[cli].in = -1;
		pending[cli].out = -1;
	}

	time = -1;
	while (running) {
		pop_waiting();
		if (time == -1)
			delta = 1000;
		else
			delta = time - gettime();
		while (delta >= 0) {
			if ((ret = poll(fd_all, nfds, delta + 1)) > 0) {
				if (fd_all[0].revents == POLLIN)
					gk_cm_read_cap();
				for (cli_idx = 0; cli_idx < cli_cnt; ++cli_idx) {
					if (fd_cli[cli_idx].revents & (POLLERR | POLLNVAL | POLLHUP)) {
						close_client(cli_idx);
						--nfds;
						continue;
					}
					if (fd_cli[cli_idx].revents & POLLOUT) {
						cli = cli_no[cli_idx];
						do {
							pop_result(cli);
						} while (try_write(cli));
					}
					if (fd_cli[cli_idx].revents & POLLIN) {
						cli = cli_no[cli_idx];
						do {
							push_waiting(cli);
						} while (try_read(cli));
					}
				}
				if (fd_all[1].revents == POLLIN) {
					if (cli_cnt < max_client && accept_client() == 0)
						++nfds;
				}
			}
			else if (ret < 0)
				perror("poll");

			time = gk_cm_conn_next_time();
			if (time == -1)
				delta = 1000;
			else
				delta = time - gettime();
		}
		time = gk_cm_conn_step();
	}

	gk_cm_finalize();
	free_mem();
}

void clean() {
	if (listenfd >= 0)
		close(listenfd);
	if (dest)
		free_dstlist(dest);
	if (cand)
		free(cand);
}

int main(int argc, char **argv) {
	int opt;

	svname.sun_family = AF_UNIX;
	svname.sun_path[0] = '\0';
	strncpy(svname.sun_path + 1, GUK_ABSTRACT_SERV_PATH, UNIX_PATH_MAX - 1);
	sv_addrlen = sizeof(sa_family_t) + 1 + strlen(GUK_ABSTRACT_SERV_PATH);

	while ((opt = getopt(argc, argv, "i:a:U:s:f:h")) != -1) {
		switch (opt) {
		case 'i':
		case 's':
			break;
		case 'a':
			svname.sun_path[0] = '\0';
			strncpy(svname.sun_path + 1, optarg, UNIX_PATH_MAX - 1);
			sv_addrlen = sizeof(sa_family_t) + 1 + strlen(GUK_ABSTRACT_SERV_PATH);
		case 'U':
			if (strlen(optarg))
				strncpy(svname.sun_path, optarg, UNIX_PATH_MAX);
			else
				strncpy(svname.sun_path, GUK_UNIX_SERV_PATH, UNIX_PATH_MAX);
			sv_addrlen = sizeof(sa_family_t) + strlen(GUK_ABSTRACT_SERV_PATH);
		case 'f':
			strncpy(config_file, optarg, 1000);
			if (config_file[999]) {
				fputs("config_file name too long\n", stderr);
				return 1;
			}
			break;
		case 'h':
		default:
			printf("USAGE:\n"
			       "# %s [OPTIONS]\n"
			       "  -a <abstract_path> : listen on the specified abstract unix domain socket.\n"
			       "  -U <unix_path>     : listen on the specified unix domain socket.\n"
			       "  -i <device>        : network interface used for sending and receiving.\n"
			       "  -f <config_file>   : configuration file name.\n"
			       "  -s <ip addr>       : the source ip address of the current machine.\n", argv[0]);
			return 0;
		}
	}

	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("socket");
		return -1;
	}
	if (fcntl(listenfd, F_SETFL, O_NONBLOCK) == -1) {
		perror("fcntl");
		goto quit;
	}
	if (setsockopt(listenfd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int)) < 0)
		perror("setsockopt");
	if (bind(listenfd, (struct sockaddr *)&svname, sv_addrlen) < 0) {
		perror("bind");
		goto quit;
	}
	if (listen(listenfd, max_client) < 0) {
		perror("listen");
		goto quit;
	}

	if (signal(SIGINT, inthandler) == SIG_ERR) {
		perror("signal");
		goto quit;
	}
	if (signal(SIGTERM, inthandler) == SIG_ERR) {
		perror("signal");
		goto quit;
	}
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
		perror("signal");
		goto quit;
	}

	if (gk_read_config_file(config_file, device, ip, &maxconn, &maxdst, candlist, &times, &time_interval, &expire_timeout, &tcp_mss, &kps, &pps))
		fprintf(stderr, "warning: configuration file %s doesn't exist.\n", config_file);
	else
		gk_cm_config(times, time_interval, expire_timeout, tcp_mss, kps, pps);

	optind = 1;
	while ((opt = getopt(argc, argv, "i:s:f:h")) != -1) {
		switch (opt) {
		case 'i':
			strncpy(device, optarg, 100);
			if (device[99]) {
				fputs("device name too long\n", stderr);
				return 1;
			}
			break;
		case 's':
			strncpy(ip, optarg, 100);
			if (ip[99]) {
				fputs("IP too long\n", stderr);
				return 1;
			}
			break;
		}
	}

	if ((dest = new_dstlist(maxdst)) == NULL) {
		fputs("new_dstlist: memory allocation failed.\n", stderr);
		goto quit;
	}
	if (candlist[0] == '\0') {
		fputs("critical: no dstlist specified.\n", stderr);
		goto quit;
	}
	cand = new_candlist(candlist, &cand_count);
	if (cand == NULL) {
		fputs("new_candlist: format error\n", stderr);
		goto quit;
	}
	if (init_dstlist(dest, cand, cand_count) != 0) {
		fputs("dstlist initialize failed.\n", stderr);
		goto quit;
	}
	if (gk_cm_init(device, ip, dest, maxconn)) {
		fputs("gk_cm_init: failed.\n", stderr);
		goto quit ;
	}
	pcap_fd = gk_cm_fd();

	run();
quit:
	clean();

	return 0;
}
