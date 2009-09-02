#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <malloc.h>
#include <pcap.h>
#include <pcap/bpf.h>

#define _NAME "Scholar Zhang"
#define _DESCR "Romance of the West Chamber"
#define _VERSION "0.3.2"
#define _DATE "Sep 2 2009"
#define _COPYING "Copyright (c) 2009, Yingying Cui. License: BSD."

pcap_t* pd;
int linktype;
u_int linkoffset;
u_int count = 0;

/*
TODO - client to server injection is to send 
an rst and an ack after syn to server, with remote 
stack's conformity of tcp protocol presumed.
So how about server to client injection? (i.e. localhost is server)
*/
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
	u_char* a = alloca(hdr->caplen);
	memcpy(a, data, hdr->caplen);
	u_char* data_aligned = a + linkoffset;

	struct libnet_ipv4_hdr* iph;
	struct libnet_tcp_hdr* tcph;
	iph = (struct libnet_ipv4_hdr*)data_aligned;
	tcph = (struct libnet_tcp_hdr*)(data_aligned + (iph->ip_hl << 2));
	u_int tcp_len = hdr->caplen - (iph->ip_hl << 2) - linkoffset;

/* XXX A libnet checksum hack */
	libnet_t l;
	l.injection_type = LIBNET_LINK;

/* XXX - on linux, syn increases seq by one, so consequent 
packets with seq == syn's should be ignored.
But windows requires this. why?
*/
	tcph->th_seq = htonl(ntohl(tcph->th_seq) - 1);

//send an rst with bad seq
	tcph->th_flags = TH_RST;
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_TCP, tcp_len) == -1){
		fprintf(stderr, "libnet_do_checksum: %s\n", l.err_buf);
		exit(1);
	}
	if(pcap_sendpacket(pd, a, hdr->caplen) == -1){
		fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(pd));
		exit(1);
	}

//send an ack
	tcph->th_flags = TH_ACK;
	if(libnet_do_checksum(&l, (void*)iph, IPPROTO_TCP, tcp_len) == -1){
		fprintf(stderr, "libnet_do_checksum: %s\n", l.err_buf);
		exit(1);
	}
	if(pcap_sendpacket(pd, a, hdr->caplen) == -1){
		fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(pd));
		exit(1);
	}

	fprintf(stderr, "Hit the Wall! #%d: ", ++count);
	fprintf(stderr, "%s:%d > ", inet_ntoa(iph->ip_src), ntohs(tcph->th_sport));
	fprintf(stderr, "%s:%d\n", inet_ntoa(iph->ip_dst), ntohs(tcph->th_dport));
}

int main(int argc, char** argv){
	//XXX why tf is stderr buffered on mingw?
	setbuf(stderr, NULL);

	if(argc < 2){
		printf("Usage: scholarzhang {-|<dev>}\nInterface not specified\n");
		return 0;
	}
	char errbuf[PCAP_ERRBUF_SIZE];

	/* inteface lookup */
	char* device = argv[1];
	if(device[0] == '-'){
		pcap_if_t* alldevs;
		if(pcap_findalldevs(&alldevs, errbuf) == -1){
			fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		pcap_if_t* d;
		int i = 0;
		for(d = alldevs; d != NULL; d = d->next){
			fprintf(stderr, "%d. %s%s: %s\n", i++, d->name,
				d->flags & PCAP_IF_LOOPBACK ? " (Loopback)" : "",
				d->description ? d->description : "(No description)");
		}
		
		fprintf(stderr, "Select an device [0-%d]: ", i-1);
		scanf("%d", &i);
		for(d = alldevs; d != NULL && i--; d = d->next);
		device = alloca(sizeof(d->name));
		strcpy(device, d->name);
		pcap_freealldevs(alldevs);
	}
	if(device == NULL)
		device = pcap_lookupdev(errbuf);
	if(device == NULL){
		fprintf(stderr, "device not found\n");
		exit(1);
	}

	fprintf(stderr, "Using device %s\n", device);

	/* start listening */
	//XXX - on mingw32, to_ms really makes a large latency 
	//rendering rst;ack useless; but on debian it's not like this
	pd = pcap_open_live(device, BUFSIZ, 0, 1, errbuf);
	if (pd == NULL){
		fprintf(stderr, "pcap_open_live(%s): %s\n", "any", errbuf);
		exit(1);
	}

	/* Compile and apply the filter */
	struct bpf_program fp;
	char filter_exp[] = "tcp and (tcp[tcpflags] = tcp-syn)";
	if (pcap_compile(pd, &fp, filter_exp, 0, 0) == -1){
		fprintf(stderr, "pcap_compile(%s): %s\n", filter_exp, pcap_geterr(pd));
		exit(1);
	}

	if (pcap_setfilter(pd, &fp) == -1){
		fprintf(stderr, "pcap_setfilter(%s): %s\n", filter_exp, pcap_geterr(pd));
		exit(1);
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
			fprintf(stderr, "Unsupported link type: %d\n", linktype);
			exit(1);
	}

	if (pcap_loop(pd, -1, handler, NULL) == 1) {
		fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(pd));
		return 1;
	}
	else 
		fprintf(stderr, "Interupted, quit now.\n");

	return 0;
}
