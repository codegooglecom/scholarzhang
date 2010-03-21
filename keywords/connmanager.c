#include "connmanager.h"
#include "dstmaintain.h"
#include "assert.h"
#include "fingerprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define _CONNMANAGER_

static libnet_t *l = NULL;
static char errbuf[LIBNET_ERRBUF_SIZE];
static pcap_t *pd = NULL;
static char pcap_errbuf[PCAP_ERRBUF_SIZE];
static uint16_t linktype, linkoffset;

#define STATUS_CHECK 0x08
#define STATUS_TYPE1 0x10
#define STATUS_TYPE2 0x20
#define STATUS_MASK 0x07

struct conncontent {
	char status;
	/*
	   0: request a (da, dp)
	   1: s
	   2: a
	   3: pa
	   4: s
	   5: expire
	   STATUS_TYPE1 or STATUS_TYPE2: we are checking keyword of this type.
	   STATUS_CHECK: check if (da, dp) works here.
	*/
	char hit; // HK_TYPE
	uint16_t sp;
	uint32_t seq, ack;
	struct dstinfo *dst;
	char *content;
	int length, next;
//	int hit_at;
	char *result;
	callback_f callback;
	void *arg;
	struct hash_t **hash;
};

#define ST_TO_HK_TYPE(status) (status >> 4)
#define HK_TO_ST_TYPE(result) (result << 4)
#define FP_TO_HK_TYPE(fingerprint) (fingerprint >> 8)

static struct connlist_t {
	struct conncontent *head;
	struct conncontent *list;
} connlist = {NULL, NULL};
// connlist has capacity = event_capa

/* event queue maintanence */
#include "heap.h"
static struct heap_t *event = NULL;
static int event_count, event_capa;
static struct dstlist *dest = NULL;

/* hash table maintanence */
#include "dst_hash.c"
// static struct hash_t **hash = NULL;
/* defined above, hash has capacity = event_capa * 3 */

static pthread_mutex_t mutex_conn, mutex_hash;
static pthread_t send_p, recv_p;

static int control_wait = 10; // in ms
static int times = 3;
static int time_interval = 30;
static int expire_timeout = 150;
static int tcp_mss = 1300;
static int kps = 0;
static int pps = 0;
#define GFW_TIMEOUT 90000 // 90 sec

static uint32_t sa;

static char running;

static const char youtube[] = "GET http://www.youtube.com HTTP/1.1\r\n\r\n";
static const int  youtube_len = sizeof(youtube);

/* (da, dp) recycle */
#include "return_dst.c"

/* connlist maintain */
static inline struct conncontent *new_conn() {
	struct conncontent *conn = connlist.head;
	if (conn)
		connlist.head = *(struct conncontent **)connlist.head;
	return conn;
}

static inline void del_conn(struct conncontent *conn) {
	*(struct conncontent **)conn = connlist.head;
	connlist.head = conn;
}

static inline void empty_connlist() {
	register struct conncontent *last;
	connlist.head = connlist.list + event_capa - 1;
	*(struct conncontent **)(connlist.head) = NULL;
	while (connlist.head > connlist.list) {
		last = connlist.head;
		*(struct conncontent **)(connlist.head = last - 1) = last;
	}
}

/* send and receive */
static void *event_loop(void *running) {
	struct conncontent *conn;
	char status;
	char type;
	libnet_ptag_t tcp = 0, ip = 0;
	uint16_t piece;
	uint16_t tot;
	long time;

	while (1) {
		if (*(char *)running == 2)
			break;
		if (event_count == 0) {
			if (*(char *)running == 1)
				break;
			usleep(1000 * control_wait);
			continue;
		}
		while (1) {
			time = event->time - gettime();
			// event->time should be a atomic operation on 32-bit machine
			if (time > 1000)
				sleep(1);
			else
				break;
		}
		pthread_mutex_lock(&mutex_conn);
		time = event->time - gettime(); // time < 1000 here
		if (time > 0)
			usleep(1000 * time);
		conn = event->data;
		status = conn->status & STATUS_MASK;
		type = ST_TO_HK_TYPE(conn->status);

		if (status == 5) {
			char result = conn->hit;
			if (conn->status & STATUS_CHECK) {
				/* connection with this dst finished,
				   if it does not work with this GFW
				   type, we will set status = 0
				   again */
				return_dst_delete_hash(dest, conn->dst, type, STATUS_CHECK | HK_TO_ST_TYPE(result), conn->hash);
				if (result & type) {
					// GFW's working, so this is not a keyword
					*conn->result = 0;
					conn->callback(result, conn->arg);
					heap_delmin(event, &event_count);
					del_conn(conn);
					goto unlock;
				}
				else {
					/* else we know nothing about if it
					   contains any keyword. */
					conn->status = HK_TO_ST_TYPE(type);
					status = 0;
				}
			}
			else if (result & ~type) {
				/* GFW no response to this type check
				   if GFW is working on this (da,
				   dp) */
				status = 1;
				conn->status = HK_TO_ST_TYPE(type) | STATUS_CHECK | 1;
			}
			else {
				// Hit
				return_dst_delete_hash(dest, conn->dst, type, HK_TO_ST_TYPE(result), conn->hash);
				*conn->result = type;
				conn->callback(result, conn->arg);
				heap_delmin(event, &event_count);
				del_conn(conn);
				goto unlock;
			}
		}

		switch (status) {
		case 0:
			conn->dst = (type == HK_TYPE1)?
				get_type1(dest):
				get_type2(dest);
			if (conn->dst == NULL) {
				// there is no (da, dp) available currently
				event->time += control_wait;
				goto next;
			}
			else
				conn->hash = hash_insert(conn->dst->da, conn->dst->dport, conn);

		case 1:
			conn->sp = libnet_get_prand(LIBNET_PR16) + 32768;
			conn->seq = libnet_get_prand(32);
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq++, 0, TH_SYN, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fprintf(stderr, "libnet_write: %s\n", errbuf);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps) usleep(1000 * tot / kps);
				}
			}
			conn->status = (conn->status & ~STATUS_MASK) | 2;
			break;

		case 2:
			conn->ack = libnet_get_prand(32) + 1;
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq, conn->ack, TH_ACK, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fprintf(stderr, "libnet_write: %s\n", errbuf);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps) usleep(1000 * tot / kps);
				}
			}
			conn->next = 0;
			conn->status = (conn->status & ~STATUS_MASK) | 3;
			break;

		case 3:
			piece = ((conn->status & STATUS_CHECK)?youtube_len:conn->length) - conn->next;
			if (piece > 0) {
				if (piece > tcp_mss)
					piece = tcp_mss;
				else
					conn->status = (conn->status & ~STATUS_MASK) | 4;
				libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq + conn->next, conn->ack + 1 + conn->next / tcp_mss % 16384, TH_ACK|TH_PUSH, 16384, 0, 0, LIBNET_TCP_H + piece, ((conn->status & STATUS_CHECK)?youtube:conn->content) + conn->next, piece, l, tcp);
				tot = LIBNET_IPV4_H + LIBNET_TCP_H + piece;
				libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
				for (time = 0; time < times; ++time) {
					if (-1 == libnet_write(l))
						fprintf(stderr, "libnet_write: %s\n", errbuf);
					else {
						if (pps) usleep(1000000 / pps);
						if (kps) usleep(1000 * tot / kps);
					}
				}
				conn->next += piece;
			}
			break;

		case 4:
			conn->seq = libnet_get_prand(32);
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq++, 0, TH_SYN, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fprintf(stderr, "libnet_write: %s\n", errbuf);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps) usleep(1000 * tot / kps);
				}
			}
			conn->status = (conn->status & ~STATUS_MASK) | 5;
			break;
		}

		if (status != 4)
			event->time += time_interval;
		else
			event->time += expire_timeout;
	next:
		heap_sink(event - 1, 1, event_count);
	unlock:
		pthread_mutex_unlock(&mutex_conn);
	}

	while (event_count) {

	}

	return NULL;
}

static void *listen_for_gfw(void *running) {
	int ret;
	struct pcap_pkthdr *pkthdr;
	uint8_t *wire;
	struct tcphdr *tcph;
	struct iphdr *iph;
	struct conncontent *conn;
	char type;

	while (*(char *)running == 0) {
		ret = pcap_next_ex(pd, &pkthdr, &wire);
		switch(linktype){
		case DLT_EN10MB:
			if (pkthdr->caplen < 14)
				continue;
			if (wire[12] == 8 && wire[13] == 0) {
				linkoffset = 14;
			} else if (wire[12] == 0x81 && wire[13] == 0) {
				linkoffset = 18;
			} else
				continue;
			break;
		}
		if (pkthdr->caplen < linkoffset)
			continue;
		iph = (struct iphdr *)(wire + linkoffset);
		tcph = (struct tcphdr *)(wire + linkoffset + (iph->ihl << 2));

		conn = hash_match(ntohl(iph->saddr), ntohs(tcph->source));
		if (conn == NULL || conn->sp != ntohs(tcph->dest))
			continue;
		type = FP_TO_HK_TYPE(gfw_fingerprint(wire + linkoffset));
		if (type == 0)
			continue;
		if (tcph->syn) {
			if (type != 2)
				// never happens
				continue;

#define WRONG fprintf(stderr, "[Warning]: Unexpected RESET from GFW. "\
		      "The result must be wrong. Stop other applications which " \
		      "is connecting the same host:port connected with this " \
		      "application, or adjust the application parameters. " \
		      "Relaunch this application after 90 seconds.\n")
			if (tcph->ack_seq == conn->seq
			    && (conn->status & STATUS_MASK) >= 4)
				conn->hit |= HK_TYPE2;
			else
				WRONG;
		}
		else if (type == 1) {
			if (tcph->seq == conn->ack
			    || (conn->status & STATUS_MASK) < 3)
				WRONG;
			else if (tcph->seq > conn->ack && tcph->seq < conn->ack + 1 + (((conn->status & STATUS_CHECK)?youtube_len:conn->length) + tcp_mss - 1) / tcp_mss)
				conn->hit |= HK_TYPE1;
		}
		else if (type == 2) {
			if ((conn->status & STATUS_MASK) < 3)
				WRONG;
			else if (tcph->seq > conn->ack && tcph->seq < conn->ack + 1 + (((conn->status & STATUS_CHECK)?youtube_len:conn->length) + tcp_mss - 1) / tcp_mss) {
				conn->hit |= HK_TYPE2;
				fprintf(stderr, "[Warning]: Special network environment. Please send the IP block of your ISP with this information to https://groups.google.com/scholarzhang-dev .\n");
			}
		}
	}

	return NULL;
}

/* connmanager */
void connmanager_config(int _control_wait, int _times, int _time_interval, int _expire_timeout, int _tcp_mss, int _kps, int _pps) {
	if (_control_wait > 0)
		control_wait = _control_wait;
	if (_times > 0)
		times = _times;
	if (_time_interval > 0)
		time_interval = _time_interval;
	if (_expire_timeout > 0)
		expire_timeout = _expire_timeout;
	if (_tcp_mss > 0)
		tcp_mss = _tcp_mss;
	if (_kps >= 0)
		kps = _kps;
	if (_pps >= 0)
		pps = _pps;
}

int add_context(char * const content, const int length, char * const result, const int type, callback_f cb, void *arg) {
	struct conncontent *conn;

	if (event_count == event_capa)
		return -1;
	pthread_mutex_lock(&mutex_conn);

	/* new conn */
	conn = new_conn();
	if (conn == NULL)
		return -1;

	conn->content = content;
	conn->length = length;
	conn->result = result;
	*conn->result = -1;
	conn->status = HK_TO_ST_TYPE(type);
	conn->hit = 0;
	conn->callback = cb;
	conn->arg = arg;

	heap_insert(event, gettime(), conn, &event_count);
	pthread_mutex_unlock(&mutex_conn);
	return 0;
}

int connmanager_run() {
	running = 0;
	if (pthread_create(&recv_p, NULL, listen_for_gfw, &running)) {
		perror("recv thread creation");
		running = 1;
		return -1;
	}
	if (pthread_create(&send_p, NULL, event_loop, &running)) {
		perror("send thread createion");
		running = 1;
		void *ret;
		pthread_join(recv_p, &ret);
		return -1;
	}
	return 0;
}

void connmanager_finalize() {
	pthread_mutex_destroy(&mutex_conn);
	pthread_mutex_destroy(&mutex_hash);

	free(event);
	free(connlist.list);
	free(hash);

	if (pd)
		pcap_close(pd);
	if (l)
		libnet_destroy(l);
}

void connmanager_sig(int sig) {
	void *ret;

	running = 2;
	pthread_join(recv_p, &ret);
	pthread_join(send_p, &ret);
	connmanager_finalize();
}

void connmanager_finish() {
	void *ret;

	running = 1;
	pthread_join(recv_p, &ret);
	pthread_join(send_p, &ret);
}

int connmanager_init(char *device, char *ip, struct dstlist *list, int capa) {
	if (pthread_mutex_init(&mutex_conn, NULL)) {
		perror("pthread_mutex_init");
		return -1;
	}
	if (pthread_mutex_init(&mutex_hash, NULL)) {
		pthread_mutex_destroy(&mutex_conn);
		perror("pthread_mutex_init");
		return -1;
	}

	if (signal(SIGINT, connmanager_sig) == SIG_ERR) {
		perror("signal");
		return -1;
	}
	if (signal(SIGTERM, connmanager_sig) == SIG_ERR) {
		perror("signal");
		return -1;
	}
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
		perror("signal");
		return -1;
	}

	if (list == NULL)
		return -1;
	else
		dest = list;

	if (capa > 0)
		event_capa = capa;
	else
		event_capa = DEFAULT_CONN;
	event = malloc(event_capa * sizeof(struct heap_t));
	connlist.list = malloc(event_capa * sizeof(struct conncontent));
	hash = malloc(3 * event_capa * sizeof(struct hash_t *));

	if (event == NULL || connlist.list == NULL || hash == NULL)
		goto quit;

	empty_connlist();
	memset(hash, 0, 3 * event_capa * sizeof(struct hash_t));
	event_count = 0;

	if ((l = libnet_init(LIBNET_RAW4, device, errbuf)) == NULL) {
		fprintf(stderr, "libnet_init: %s\n", errbuf);
		goto quit;
	}
	if (ip == NULL) {
		sa = libnet_get_ipaddr4(l);
		ip = inet_ntoa(*(struct in_addr *)&sa);
	}
	else
		sa = inet_addr(ip);
	sa = ntohs(sa);

	if (libnet_seed_prand(l) == -1) {
		fprintf(stderr, "libnet_seed_prand: %s\n", errbuf);
		goto quit;
	}
	pd = pcap_open_live((device?device:libnet_getdevice(l)), 100, 0, control_wait, pcap_errbuf);
	if (pd == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", pcap_errbuf);
		goto quit;
	}
	char filter_exp[50] = "tcp and dst ";
	struct bpf_program fp;
	strcat(filter_exp, ip);
	if ( pcap_compile(pd, &fp, filter_exp, 1, 0) == -1
	     || pcap_setfilter(pd, &fp) == -1 ) {
		pcap_perror(pd, "pcap");
		goto quit;
	}

	linktype = pcap_datalink(pd);
	switch(linktype){
#ifdef DLT_NULL
		case DLT_NULL:
			linkoffset = 4;
			break;
#endif
		case DLT_EN10MB:
			linkoffset = 14;
			break;
		case DLT_PPP:
			linkoffset = 4;
			break;

		case DLT_RAW:
		case DLT_SLIP:
			linkoffset = 0;
			break;
#define DLT_LINUX_SLL	113
		case DLT_LINUX_SLL:
			linkoffset = 16;
			break;
#ifdef DLT_FDDI
		case DLT_FDDI:
			linkoffset = 21;
			break;
#endif
#ifdef DLT_PPP_SERIAL
		case DLT_PPP_SERIAL:
			linkoffset = 4;
			break;
#endif
		default:
			fprintf(stderr, "Unsupported link type: %d\n", linktype);
			goto quit;
	}


	fprintf(stderr, "Listening on device %s with IP address %s\n", device, ip);
	return 0;

quit:
	connmanager_finalize();
	return -1;
}
