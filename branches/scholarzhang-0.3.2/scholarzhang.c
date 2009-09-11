#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <libnet.h>
#include <pcap.h>
#include <pcap/bpf.h>

#define _NAME "Scholar Zhang"
#define _DESCR "Romance of the West Chamber"
#define _VERSION "0.3.2"
#define _DATE "Sep 2 2009"
#define _COPYING "Copyright (c) 2009, Yingying Cui. License: BSD."

pcap_t* pd;
int linktype;
guint linkoffset;

gboolean cfg_debug = FALSE;
char* cfg_interface = NULL;

GOptionEntry gopts[] = {
	{"debug", 'd', 0, G_OPTION_ARG_NONE, &cfg_debug, 
		"Enable debug", NULL},
	{"interface", 'i', 0, G_OPTION_ARG_STRING, &cfg_interface, 
		"Interface to listen on", NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

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
	guchar* a = g_alloca(hdr->caplen);
	memcpy(a, data, hdr->caplen);
	guchar* data_aligned = a + linkoffset;

	struct libnet_ipv4_hdr* iph;
	struct libnet_tcp_hdr* tcph;
	iph = (struct libnet_ipv4_hdr*)data_aligned;
	tcph = (struct libnet_tcp_hdr*)(data_aligned + (iph->ip_hl << 2));
	guint tcp_len = hdr->caplen - (iph->ip_hl << 2) - linkoffset;

/* XXX A libnet checksum hack */
	libnet_t l;
	l.injection_type = LIBNET_LINK;

/* syn increases seq by one, so consequent 
packets with seq == syn's should be ignored
But windows requires this. why? // What does this sentence mean? windows server expect this or windows client?
*/
	tcph->th_seq = htonl(ntohl(tcph->th_seq) - 1);

//send an rst with bad seq
	tcph->th_flags = TH_RST;
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_TCP, tcp_len) == -1)
		g_warning("libnet_do_checksum: %s", l.err_buf);
	if(pcap_sendpacket(pd, a, hdr->caplen) == -1)
		g_debug("pcap_sendpacket: %s", pcap_geterr(pd));

//send an ack
	tcph->th_flags = TH_ACK;
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_TCP, tcp_len) == -1)
		g_warning("libnet_do_checksum: %s", l.err_buf);
	if(pcap_sendpacket(pd, a, hdr->caplen) == -1)
		g_debug("pcap_sendpacket: %s", pcap_geterr(pd));

	g_debug("injected %d>%d", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
}

void quiet(const gchar* a, GLogLevelFlags b, const gchar* c, gpointer d){
        (void)a; (void)b; (void)c; (void)d;
}

int main(int argc, char** argv){
	GError* gerr;
	/* options */
	GOptionContext* context = g_option_context_new(NULL);
	//g_option_context_set_summary(context, _DESCR);
	g_option_context_add_main_entries(context, gopts, NULL);
	if(!g_option_context_parse(context, &argc, &argv, &gerr))
		g_error("g_option_context_parse: %s", gerr->message);
	g_option_context_free(context);
	
	if(!cfg_debug)
		g_log_set_handler(NULL, G_LOG_LEVEL_DEBUG | G_LOG_FLAG_FATAL
 						| G_LOG_FLAG_RECURSION, quiet, NULL);

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp and (tcp[tcpflags] = tcp-syn)";
	/* start listening */
	if(cfg_interface == NULL)
		cfg_interface = pcap_lookupdev(errbuf);
	if(cfg_interface == NULL)
		g_error("interface not found");
	g_debug("Using interface %s", cfg_interface);

	pd = pcap_open_live(cfg_interface, BUFSIZ, 0, 1000, errbuf);
	if (pd == NULL)
		g_error("pcap_open_live(%s): %s", "any", errbuf);

	/* Compile and apply the filter */
	if (pcap_compile(pd, &fp, filter_exp, 0, 0) == -1)
		g_error("pcap_compile(%s): %s", filter_exp, pcap_geterr(pd));

	if (pcap_setfilter(pd, &fp) == -1)
		g_error("pcap_setfilter(%s): %s", filter_exp, pcap_geterr(pd));

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
#define DLT_LINUX_SLL   113
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
			g_error("Unsupported link type: %d", linktype);
	}

	if (pcap_loop(pd, -1, handler, NULL) == 1) {
		g_critical("pcap_loop: %s", pcap_geterr(pd));
		return 1;
	}
	else
		g_debug("Interupted, quit now.");

	return 0;
}
