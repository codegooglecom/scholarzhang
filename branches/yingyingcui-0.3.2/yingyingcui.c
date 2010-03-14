#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>

#define _NAME "YingYing CUI"
#define _DESCR "Romance of the West Chamber"
#define _VERSION "0.3.2"
#define _DATE "Sep 2 2009"
#define _COPYING "Copyright (c) 2009, Yingying Cui. License: BSD."

pcap_t *pd;
int linktype;
uint32_t linkoffset;

char cfg_debug = 0;
char *cfg_interface = NULL;
uint32_t cfg_wait = 10;
uint32_t cfg_times = 3;
struct timeval delay;

void CUI_error(char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void CUI_warning(char *fmt, ...) {
	(void)fmt;
}

void CUI_debug(char *fmt, ...) {
	if (cfg_debug) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

struct delayed_packet {
	struct timeval ts;
	uint32_t len;
	uint8_t *buf;
	uint32_t ip_off;
	uint32_t tcp_len;
};

#define QUEUE_LEN 2000
struct delayed_packet delayed[QUEUE_LEN];
int queue_head = 0, queue_rear = 0, queue_count = 0;

pthread_t delay_p;
void *none;
char running = 0;

void *send_sa_and_rst() {
	libnet_t l;
	l.injection_type = LIBNET_LINK;
	struct timeval tv, slp;
	struct delayed_packet *d;
	void *h;
	uint32_t i;

	while (1) {
		if (!running && queue_count == 0)
			return NULL;
		while (queue_count == 0)
			usleep(delay.tv_usec);
		d = delayed + queue_head;

		gettimeofday(&tv, NULL);
		if (timercmp(&d->ts, &tv, >))
			timersub(&d->ts, &tv, &slp);
		else
			timerclear(&slp);
		sleep(slp.tv_sec);
		usleep(slp.tv_usec);

		h = (d->buf + d->ip_off);
		if(libnet_do_checksum(&l, h, IPPROTO_TCP, d->tcp_len) == -1)
			CUI_warning("libnet_do_checksum: %s", l.err_buf);
		if(libnet_do_checksum(&l, h, IPPROTO_IP, d->tcp_len) == -1)
			CUI_warning("libnet_do_checksum: %s", l.err_buf);
		if (pcap_sendpacket(pd, d->buf, d->len) == -1)
			CUI_debug("pcap_sendpacket: %s", pcap_geterr(pd));

		CUI_debug("send original sa %d>%d", ntohs(((struct libnet_tcp_hdr *)h)->th_sport), ntohs(((struct libnet_tcp_hdr *)h)->th_dport));

		h += ((struct libnet_ipv4_hdr *)h)->ip_hl << 2;
		((struct libnet_tcp_hdr *)h)->th_flags = TH_RST;
//		((struct libnet_tcp_hdr *)h)->th_seq--;
		((struct libnet_tcp_hdr *)h)->th_ack = 0;
		if(libnet_do_checksum(&l, h, IPPROTO_TCP, d->tcp_len) == -1)
			CUI_warning("libnet_do_checksum: %s", l.err_buf);
		if(libnet_do_checksum(&l, h, IPPROTO_IP, d->tcp_len) == -1)
			CUI_warning("libnet_do_checksum: %s", l.err_buf);
		for (i = 0; i < cfg_times; ++i)
			if (pcap_sendpacket(pd, d->buf, d->len) == -1)
				CUI_debug("pcap_sendpacket: %s", pcap_geterr(pd));

		CUI_debug("send r %d>%d", ntohs(((struct libnet_tcp_hdr *)h)->th_sport), ntohs(((struct libnet_tcp_hdr *)h)->th_dport));

		free(d->buf);
		--queue_count; queue_head = (queue_head + 1) % QUEUE_LEN;
	}
}

void enqueue_sa(uint8_t *data, uint32_t len, uint32_t ip_off, uint32_t tcp_len, const struct timeval *ts) {
	struct delayed_packet *d;

	while (queue_count == QUEUE_LEN);
	++queue_count;
	d = delayed + queue_rear;
	timeradd(ts, &delay, &d->ts);
	d->len = len;
	d->buf = data;
	d->ip_off = ip_off;
	d->tcp_len = tcp_len;

	queue_rear = (queue_rear + 1) % QUEUE_LEN;
}

void handler(u_char* _, const struct pcap_pkthdr *hdr, const u_char* data){
	(void)_;
	switch(linktype){
		case DLT_EN10MB:
			if (hdr->caplen < 14)
				return;
			if (data[12] == 8 && data[13] == 0) {
				linkoffset = 14;
			} else if (data[12] == 0x81 && data[13] == 0) {
				linkoffset = 18;
			} else
				return;
			break;
		default:;
	}
	if (hdr->caplen < linkoffset)
		return;

/* FIXME - different alignment padding on some platform

...
*/

/* NB: use pcap_sendpacket() instead of libnet_write()
for faster packet injection
*/
	uint8_t* a = malloc(hdr->caplen);
	memcpy(a, data, hdr->caplen);
	uint8_t* data_aligned = a + linkoffset;

	struct libnet_ipv4_hdr* iph;
	struct libnet_tcp_hdr* tcph;
	iph = (struct libnet_ipv4_hdr*)data_aligned;
	tcph = (struct libnet_tcp_hdr*)(data_aligned + (iph->ip_hl << 2));
	uint32_t tcp_len = hdr->caplen - (iph->ip_hl << 2) - linkoffset;

/* XXX A libnet checksum hack */
	libnet_t l;
	l.injection_type = LIBNET_LINK;

	iph->ip_ttl = 255;
	tcph->th_ack = htonl(ntohl(tcph->th_ack) - 1);

//send an ack with correct seq but bad ack
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_TCP, tcp_len) == -1)
		CUI_warning("libnet_do_checksum: %s", l.err_buf);
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_IP, tcp_len) == -1)
		CUI_warning("libnet_do_checksum: %s", l.err_buf);
	uint32_t i;
	for (i = 0; i < cfg_times; ++i)
		if(pcap_sendpacket(pd, a, hdr->caplen) == -1)
			CUI_debug("pcap_sendpacket: %s", pcap_geterr(pd));
	CUI_debug("injected %d>%d", ntohs(tcph->th_sport), ntohs(tcph->th_dport));

	tcph->th_ack = htonl(ntohl(tcph->th_ack) + 1);
	enqueue_sa(a, hdr->caplen, linkoffset, tcp_len, &hdr->ts);
}

int options(int argc, char** argv) {
	int opt;

	struct option longoptions[] = {
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "di:t:x:", longoptions, 0)) != -1) {
		switch(opt) {
		case 'd':
			cfg_debug = 1;
			break;
		case 'i':
			cfg_interface = optarg;
			break;
		case 't':
			cfg_wait = atoi(optarg);
			break;
		case 'x':
			cfg_times = atoi(optarg);
			break;
		default:
			printf("USAGE: \n"
			       "  %s [OPTIONS]\n"
			       "  -t <int>    : Delay before send the correct syn/ack, Unit in ms. Default 10.\n"
			       "  -i <device> : Interface to listen on.\n"
			       "  -x <int>    : Insert how many packet once.\n"
			       "  -d	      : Enable debug.\n\n", argv[0]);
			return 1;
		}
	}
	return 0;
}

int main(int argc, char** argv){
	/* options */
	if (options(argc, argv)) return 1;

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp and (tcp[tcpflags] = (tcp-syn|tcp-ack))";
	/* start listening */
	if(cfg_interface == NULL)
		cfg_interface = pcap_lookupdev(errbuf);
	if(cfg_interface == NULL)
		CUI_error("interface not found");
	CUI_debug("Using interface %s", cfg_interface);

	pd = pcap_open_live(cfg_interface, BUFSIZ, 0, 1000, errbuf);
	if (pd == NULL)
		CUI_error("pcap_open_live(%s): %s", "any", errbuf);

	/* Compile and apply the filter */
	if (pcap_compile(pd, &fp, filter_exp, 0, 0) == -1)
		CUI_error("pcap_compile(%s): %s", filter_exp, pcap_geterr(pd));

	if (pcap_setfilter(pd, &fp) == -1)
		CUI_error("pcap_setfilter(%s): %s", filter_exp, pcap_geterr(pd));

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
			CUI_error("Unsupported link type: %d", linktype);
	}

	running = 1;
	pthread_create(&delay_p, NULL, send_sa_and_rst, NULL);

	timerclear(&delay);
	delay.tv_usec = cfg_wait * 1000;

	int ret = pcap_loop(pd, -1, handler, NULL);
	running = 0;
	pthread_join(delay_p, &none);
	if (ret == 1) {
		CUI_error("pcap_loop: %s", pcap_geterr(pd));
		return 1;
	}
	else
		CUI_debug("Interupted, quit now.");

	return 0;
}
