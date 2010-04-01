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
#define STATUS_ERROR 0x40
#define STATUS_MASK 0x07

struct conncontent {
	char status;
	/*
	   0: request a (da, dp)
	   1: s
	   2: a
	   3: pa;a---fpa;a
	   4: s;r
	   5: expire
	   STATUS_TYPE1 or STATUS_TYPE2: we are checking keyword of this type.
	   STATUS_CHECK: check if (da, dp) works here.
	*/
	char hit; // HK_TYPE
	uint16_t sp;
	uint32_t seq, ack, new_seq;
	struct dstinfo *dst;
	char *content;
	int length, next;
//	int hit_at;
	char *result;
	gk_callback_f callback;
	void *arg;
	struct hash_t **hash;
};

#define ST_TO_HK_TYPE(status) ((status >> 4) & 3)
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
static int expire_timeout = 200;
static int tcp_mss = 1300;
static double kps = 0;
static int pps = 0;
#define GFW_TIMEOUT 90000 // 90 sec

static uint32_t sa;

static char running = -1;

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

static inline void clear_queue() {
	struct conncontent *conn;

	pthread_mutex_lock(&mutex_conn);
	pthread_mutex_lock(&mutex_hash);
	while (event_count) {
		conn = event->data;
		if (conn->dst) {
			return_dst_delete_hash(dest, conn->dst, ST_TO_HK_TYPE(conn->status), HK_TO_ST_TYPE(conn->hit), conn->hash);
		}
		heap_delmin(event, &event_count);
		conn->callback(conn->content, -1, conn->arg);
		del_conn(conn);
	}
	pthread_mutex_unlock(&mutex_hash);
	pthread_mutex_unlock(&mutex_conn);
}

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
			pthread_mutex_lock(&mutex_conn);
			time = event->time - gettime();
			pthread_mutex_unlock(&mutex_conn);
			// Since heap's data is modified by memcpy, event->time is not a atomic register.
			if (time > control_wait)
				usleep(1000 * control_wait);
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

		time = gettime();
		if (status == 5) {
			char result = conn->hit;
			if (conn->status & STATUS_CHECK) {
				/* connection with this dst finished,
				   if it does not work with this GFW
				   type, we will set status = 0
				   again */
				pthread_mutex_lock(&mutex_hash);
				if (result & type) {
					// GFW's working, so this is not a keyword
					*conn->result = 0;
					conn->callback(conn->content, HK_TO_ST_TYPE(result) | type, conn->arg);
					heap_delmin(event, &event_count);
					del_conn(conn);
				}
				else {
					/* else we know nothing about if it
					   contains any keyword. */
					fprintf(stderr, "[information]: GFW type%d is not working on (local:%d, %s:%d).\n", type, conn->sp, inet_ntoa(*(struct in_addr *)&conn->dst->da), conn->dst->dport);
					conn->status = HK_TO_ST_TYPE(type);
					conn->hit = 0;
					status = 0;
				}
				return_dst_delete_hash(dest, conn->dst, type, STATUS_CHECK | HK_TO_ST_TYPE(result), conn->hash);
				pthread_mutex_unlock(&mutex_hash);
				if (result & type)
					goto unlock;
			}
			else if ((result & type) == 0) {
				/* GFW no response to this type check
				   if GFW is working on this (da,
				   dp) */
				status = 1;
				conn->status = HK_TO_ST_TYPE(type) | STATUS_CHECK | 1;
			}
			else {
				// Hit or in consequent resetting status
				pthread_mutex_lock(&mutex_hash);
				if (conn->status & STATUS_ERROR) {
					conn->status = HK_TO_ST_TYPE(type);
					conn->hit = 0;
					status = 0;
				}
				else {
					//fprintf(stderr, "result: %d, (local:%d, %s:%d)\n", result, conn->sp, inet_ntoa(*(struct in_addr *)&conn->dst->da), conn->dst->dport);
					*conn->result = result;
					conn->callback(conn->content, HK_TO_ST_TYPE(result) | type, conn->arg);
					heap_delmin(event, &event_count);
					del_conn(conn);
				}
				return_dst_delete_hash(dest, conn->dst, type, HK_TO_ST_TYPE(result), conn->hash);
				pthread_mutex_unlock(&mutex_hash);
				if ((conn->status & STATUS_ERROR) == 0)
					goto unlock;
			}
		}

		//int i;
		switch (status) {
		case 0:
			//for (i = 11; conn->content[i] != ' '; ++i)
			//	putchar(conn->content[i]);
			//putchar(' ');
			conn->sp = libnet_get_prand(LIBNET_PR16) + 32768;
			conn->dst = (type == HK_TYPE1)?
				get_type1(dest):
				get_type2(dest);
			if (conn->dst == NULL) {
				// there is no (da, dp) available currently
				event->time += control_wait;
				goto next;
			}
			else {
				//printf("(local:%d, %s:%d)\n", conn->sp, inet_ntoa(*(struct in_addr *)&conn->dst->da), conn->dst->dport);
				pthread_mutex_lock(&mutex_hash);
				conn->hash = hash_insert(conn->dst->da, conn->dst->dport, conn);
				pthread_mutex_unlock(&mutex_hash);
			}

		case 1:
			conn->seq = libnet_get_prand(LIBNET_PR32);
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq++, 0, TH_SYN, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fputs(errbuf, stderr);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps >= 1) usleep(1000 * tot / kps);
				}
			}
			conn->status = (conn->status & ~STATUS_MASK) | 2;
			break;

		case 2:
			conn->ack = libnet_get_prand(LIBNET_PR32) + 1;
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq, conn->ack, TH_ACK, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fputs(errbuf, stderr);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps >= 1) usleep(1000 * tot / kps);
				}
			}
			conn->next = 0;
			conn->status = (conn->status & ~STATUS_MASK) | 3;
			break;

		case 3:
			piece = ((conn->status & STATUS_CHECK)?youtube_len:conn->length) - conn->next;
			type = TH_ACK|TH_PUSH;
			if (piece > 0) {
				if (piece > tcp_mss)
					piece = tcp_mss;
				else {
					conn->status = (conn->status & ~STATUS_MASK) | 4;
					type |= TH_FIN;
				}
				tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq + conn->next, conn->ack + 1 + conn->next / tcp_mss % 16384, type, 16384, 0, 0, LIBNET_TCP_H + piece, ((conn->status & STATUS_CHECK)?youtube:conn->content) + conn->next, piece, l, tcp);
				tot = LIBNET_IPV4_H + LIBNET_TCP_H + piece;
				ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
				for (time = 0; time < times; ++time) {
					if (-1 == libnet_write(l))
						fputs(errbuf, stderr);
					else {
						if (pps) usleep(1000000 / pps);
						if (kps >= 1) usleep(1000 * tot / kps);
					}
				}
				conn->next += piece;

				tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->seq + conn->next, conn->ack + 1 + conn->next / tcp_mss % 16384, TH_ACK, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
				tot = LIBNET_IPV4_H + LIBNET_TCP_H;
				ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
				for (time = 0; time < times; ++time) {
					if (-1 == libnet_write(l))
						fputs(errbuf, stderr);
					else {
						if (pps) usleep(1000000 / pps);
						if (kps >= 1) usleep(1000 * tot / kps);
					}
				}
			}
			break;

		case 4:
			conn->new_seq = libnet_get_prand(LIBNET_PR32);
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->new_seq++, 0, TH_SYN, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fputs(errbuf, stderr);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps >= 1) usleep(1000 * tot / kps);
				}
			}
			tcp = libnet_build_tcp(conn->sp, conn->dst->dport, conn->new_seq, 0, TH_RST, 16384, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
			tot = LIBNET_IPV4_H + LIBNET_TCP_H;
			ip = libnet_build_ipv4(tot, 0, 0, IP_DF, 64, IPPROTO_TCP, 0, sa, conn->dst->da, NULL, 0, l, ip);
			for (time = 0; time < times; ++time) {
				if (-1 == libnet_write(l))
					fputs(errbuf, stderr);
				else {
					if (pps) usleep(1000000 / pps);
					if (kps >= 1) usleep(1000 * tot / kps);
				}
			}
			conn->status = (conn->status & ~STATUS_MASK) | 5;
			break;
		}

		if (status != 4)
			event->time = time + time_interval;
		else
			event->time = time + expire_timeout;
	next:
		heap_sink(event - 1, 1, event_count);
	unlock:
		pthread_mutex_unlock(&mutex_conn);
	}

	clear_queue();

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
	uint32_t hit_range;
	uint32_t seq;

	while (*(char *)running == 0) {
		ret = pcap_next_ex(pd, &pkthdr, &wire);
		if (ret != 1) {
			if (ret == -1)
				pcap_perror(pd, "listen_for_gfw");
			continue;
		}
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

		pthread_mutex_lock(&mutex_hash);
		conn = hash_match(iph->saddr, ntohs(tcph->source));
		if (conn == NULL || conn->sp != ntohs(tcph->dest))
			goto release;
		type = FP_TO_HK_TYPE(gfw_fingerprint(wire + linkoffset));
		if (type == 0)
			goto release;

#define WRONG { fputs("[Warning]: Unexpected RESET from GFW. "		\
		      "The result must be wrong. Stop other applications which " \
		      "is connecting the same host:port connected with this " \
		      "application, or adjust the application parameters. " \
		      "Resume keyword testing after 90 seconds.\n", stderr); \
		fprintf(stderr, "type%d, flag:%s%s%s, (local:%d, %s:%d), seq: %u, "\
			"ack: %u, conn->seq: %u, conn->ack: %u, conn->new_seq: %u, " \
			"conn->status: %x\n", type, tcph->syn?"s":"", tcph->rst?"r":"",	\
			tcph->ack?"a":"", conn->sp, inet_ntoa(*(struct in_addr *)&conn->dst->da), \
			conn->dst->dport, ntohl(tcph->seq), ntohl(tcph->ack_seq), \
			conn->seq, conn->ack, conn->new_seq, conn->status); \
		conn->status |= STATUS_ERROR; }

		if (tcph->syn) {
			if (type == 2) {
				conn->hit |= HK_TYPE2;
				seq = ntohl(tcph->ack_seq);
				if ( ((conn->status & STATUS_MASK) < 4 || seq != conn->new_seq )
				     && (seq != conn->seq || (conn->status & STATUS_CHECK) == 0) )
					WRONG
			}
		}
		else {
			hit_range = conn->ack + 1 + (((conn->status & STATUS_CHECK)?youtube_len:conn->length) + tcp_mss - 1) / tcp_mss;
			seq = ntohl(tcph->seq);

			if (type == 1) {
				conn->hit |= HK_TYPE1;
				if (conn->status & STATUS_CHECK) {
					if (seq < conn->ack || seq > hit_range || (conn->status & STATUS_MASK) < 2)
						WRONG
				}
				else {
					if (seq <= conn->ack || seq > hit_range || (conn->status & STATUS_MASK) < 3)
					    WRONG
//					else
//						conn->hit_at = seq - conn->ack - 1;
				}
			}
			else {
				conn->hit |= HK_TYPE2;
				if ( (conn->status & STATUS_CHECK) == 0	 ) {
					if ( (ntohl(tcph->ack_seq) != conn->new_seq) || (conn->status & STATUS_MASK) < 4 ) {
						if ((conn->status & STATUS_MASK) < 3)
							WRONG
						else if (seq > hit_range) {
							seq -= 1460;
							if (seq > hit_range) {
								seq -= 2920;
								if (seq <= conn->ack)
									WRONG
							}
							if (seq <= conn->ack)
								WRONG
						}
						else if (seq <= conn->ack)
							WRONG
//						else {
//							conn->hit_at = seq - conn->ack - 1;
//							fputs("[Warning]: Special network environment. Please send the IP block of your ISP with this information to https://groups.google.com/scholarzhang-dev .\n", stderr);
//						}
					}
				}
			}
		}
#undef WRONG
	release:
		pthread_mutex_unlock(&mutex_hash);
	}

	return NULL;
}

/* connmanager */
void gk_cm_config(int _control_wait, int _times, int _time_interval, int _expire_timeout, int _tcp_mss, double _kps, int _pps) {
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
	if (_kps >= 1) {
		kps = _kps;
		pps = 0;
	}
	if (_pps >= 0) {
		kps = 0;
		pps = _pps;
	}
}

int gk_add_context(char * const content, const int length, char * const result, const int type, gk_callback_f cb, void *arg) {
	if (event_count == event_capa)
		return -1;
	pthread_mutex_lock(&mutex_conn);

	/* new conn */
	struct conncontent *conn;
	conn = new_conn();
	if (conn == NULL)
		return -1;

	conn->content = content;
	conn->length = length;
	conn->result = result;
	*result = -1;
	conn->status = HK_TO_ST_TYPE(type);
	conn->hit = 0;
	conn->callback = cb;
	conn->arg = arg;

	heap_insert(event, gettime(), conn, &event_count);
	pthread_mutex_unlock(&mutex_conn);
	if (running != 0) {
		clear_queue();
		return -2;
	}
	return 0;
}

int gk_cm_run() {
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

void gk_cm_finalize() {
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

void gk_cm_abort() {
	void *ret;

	if (running == 0) {
		running = 2;
		pthread_join(recv_p, &ret);
		pthread_join(send_p, &ret);
	}
}

void gk_cm_finish() {
	void *ret;

	if (running == 0) {
		running = 1;
		pthread_join(recv_p, &ret);
		pthread_join(send_p, &ret);
	}
}

int gk_cm_init(char *device, char *ip, struct dstlist *list, int capa) {
	if (device == NULL || device[0] == '\0') {
		pcap_if_t *alldevsp;
		if (pcap_findalldevs(&alldevsp, pcap_errbuf) != 0) {
			fprintf(stderr, "pcap_findalldevs: %s", pcap_errbuf);
			return -1;
		}
		strcpy(device, alldevsp->name);
		pcap_freealldevs(alldevsp);
	}

	if (pthread_mutex_init(&mutex_conn, NULL)) {
		perror("pthread_mutex_init");
		return -1;
	}
	if (pthread_mutex_init(&mutex_hash, NULL)) {
		pthread_mutex_destroy(&mutex_conn);
		perror("pthread_mutex_init");
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
	memset(hash, 0, 3 * event_capa * sizeof(struct hash_t *));
	event_count = 0;

	if ((l = libnet_init(LIBNET_RAW4, device, errbuf)) == NULL) {
		fputs(errbuf, stderr);
		goto quit;
	}
	if (ip == NULL || ip[0] == '\0') {
		sa = libnet_get_ipaddr4(l);
		ip = inet_ntoa(*(struct in_addr *)&sa);
	}
	else
		sa = inet_addr(ip);

	if (libnet_seed_prand(l) == -1) {
		fputs(errbuf, stderr);
		goto quit;
	}
	pd = pcap_open_live(device, 100, 0, control_wait, pcap_errbuf);
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
	gk_cm_finalize();
	return -1;
}
