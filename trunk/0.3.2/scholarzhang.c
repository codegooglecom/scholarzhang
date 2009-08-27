#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#include <libnet.h>
#include <pcap/pcap.h>

#define _NAME "Scholar Zhang"
#define _DESCR "Romance of the West Chamber"
#define _VERSION "0.3.2"
#define _DATE "Aug 27 2009"
#define _COPYING "Copyright (c) 2009, Yingying Cui. License: BSD."

void inject(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet(struct libnet_ipv4_hdr*, struct libnet_tcp_hdr*);
void init(int argc, char** argv);
void sigh(int _);

GError* gerr;

libnet_t* l;
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_ptag_t tcp;
libnet_ptag_t ip;

pcap_t* handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto \\tcp and (tcp[tcpflags] = tcp-syn)";

struct timeval ref_ts, now;


/* conf vars */
guint cfg_pcaptimeout = 1;
gboolean cfg_quiet = FALSE;

GOptionEntry gopts[] = {
	{"quiet", 'q', 0, G_OPTION_ARG_NONE, &cfg_quiet, 
		"run silently", NULL},
	{"pcaptimeout", 'p', 0, G_OPTION_ARG_INT, &cfg_pcaptimeout, 
		"READ_TIMEOUT parameter for pcap. Unit in ms, default is 1.\
WARNING: This parameter must be smaller than the latency from this host\
	 to the wall. You can increace it a bit to improve the preformance\
	 of the program. If unsure, keep the defaults.", NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

char* addr2name(guint _addr){
	static char name[NI_MAXHOST];
	name[0] = 0;
//	struct sockaddr_in addr;
//	addr.sin_family = AF_INET;
//	addr.sin_addr.s_addr = _addr;
// 	if(cfg_resolve){
// 		getnameinfo((struct sockaddr*)&addr, sizeof(addr), name, 
// 								NI_MAXHOST, NULL, 0, 0);
// 	}else{
		inet_ntop(AF_INET, (struct in_addr*)&_addr, name, NI_MAXHOST);
// 	}
	return name;
}

void print_packet(struct libnet_ipv4_hdr* iph, struct libnet_tcp_hdr* tcph){
	gboolean first = TRUE;
#define PRINTFLAG(f) \
if(tcph->th_flags & TH_##f){\
	if(!first)fputc(' ', stderr);\
	fprintf(stderr,#f);\
	first=FALSE;\
}
	PRINTFLAG(FIN)
	PRINTFLAG(SYN)
	PRINTFLAG(RST)
	PRINTFLAG(PUSH)
	PRINTFLAG(ACK)
	PRINTFLAG(URG)
	PRINTFLAG(ECE)
	PRINTFLAG(CWR)
	fprintf(stderr, "\n	to %s:%hu (id=%04x ttl=%hhu seq=%08x)\n", 
					addr2name(iph->ip_dst.s_addr), 
					ntohs(tcph->th_dport),
					ntohs(iph->ip_id),
					iph->ip_ttl,
					ntohl(tcph->th_seq));
	fprintf(stderr, "	from %s:%hu\n", 
					addr2name(iph->ip_src.s_addr), 
					ntohs(tcph->th_sport));
}

void init(int argc, char** argv){
	g_thread_init(NULL);

	/* options */
	GOptionContext* context = g_option_context_new(NULL);
	//g_option_context_set_summary(context, _DESCR);
	g_option_context_add_main_entries(context, gopts, NULL);
	if(!g_option_context_parse(context, &argc, &argv, &gerr))
		g_error("g_option_context_parse: %s", gerr->message);
	g_option_context_free(context);

	/* init libnet */
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if(l == NULL)
		g_error("libnet_init: %s", errbuf);

	/* install signal handler */
	signal(SIGINT, sigh);
	signal(SIGQUIT, sigh);
	signal(SIGTERM, sigh);
}

void sigh(int _){
	(void)_;
	pcap_breakloop(handle);
}

void inject(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
	struct libnet_ipv4_hdr *iph;
	struct libnet_tcp_hdr *tcph;
	
	timersub(&header->ts, &ref_ts, &now);
	fprintf(stderr, "%d.%06d\t", now.tv_sec, now.tv_usec);
	iph = (struct libnet_ipv4_hdr*)(packet + 2 + LIBNET_ETH_H);
	tcph = (struct libnet_tcp_hdr*)(packet + 2 + LIBNET_ETH_H + LIBNET_IPV4_H);
	
	print_packet(iph, tcph);
	
	tcp = libnet_build_tcp(ntohs(tcph->th_sport), ntohs(tcph->th_dport), ntohl(tcph->th_seq) - 1, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, IP_DF, iph->ip_ttl, IPPROTO_TCP, 0, iph->ip_src.s_addr, iph->ip_dst.s_addr, NULL, 0, l, ip);
	if(-1 == libnet_write(l))
		g_warning("libnet_write: %s\n", libnet_geterror(l));
	
	gettimeofday(&now, NULL);
	timersub(&now, &ref_ts, &now);
	fprintf(stderr, "inject it at %d.%06d\n\n", now.tv_sec, now.tv_usec);
}

int main(int argc, char** argv){
	init(argc, argv);

	/* get start time */
	gettimeofday(&ref_ts, NULL);
	
	/* start listening */
	handle = pcap_open_live("any", BUFSIZ, 1, cfg_pcaptimeout, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", "any", errbuf);
		return 2;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	if (pcap_loop(handle, -1, inject, NULL) == 1) {
		g_debug("%s", pcap_geterr(handle));
		return 2;
	}
	else
		g_debug("Interupted, quit now.");

	return 0;
}
