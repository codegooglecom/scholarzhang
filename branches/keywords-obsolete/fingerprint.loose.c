#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "fingerprint.h"

#define	IP_RF 0x8000
#define	IP_DF 0x4000
#define	IP_MF 0x2000
#define	IP_OFFMASK 0x1fff
#define intcpy(dest, src) (*(int*)(dest) = *(int*)(src), 4)


static int itoa(char *s, unsigned int i){
	int len = (i < 10 ? 1 : i < 100 ? 2 : i < 1000 ? 3 : \
i < 10000 ? 4 : i < 100000 ? 5 : i < 1000000 ? 6 : \
i < 10000000 ? 7 : i < 100000000 ? 8 : i < 1000000000 ? 9 : 10);
	s += len;
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
		*--s=(char)('0'+i);
	return len;
}
#define unless(exp) if(!(exp))

int gfw_fingerprint(const void *buf){
	const struct iphdr *ip = buf;
	int m1 = 1, m1a = 1, m2 = 1, m2a = 1;
	int type;
	unless(ntohs(ip->id) == 64)
		m1=0, m1a=0;
	unless(ntohs(ip->frag_off) & IP_DF)
		m2=0, m2a=0;
	else
		m1=0, m1a=0;
	if(ip->protocol == IPPROTO_TCP){
		const struct tcphdr *tcp = buf + (ip->ihl << 2);
		unless((tcp->doff << 2) - sizeof(struct tcphdr) == 0)
			m1=0, m1a=0, m2=0, m2a=0;
		if(ip->id == 0 && (tcp->window == 0 || ntohs(tcp->window) > 888))
			m1=0, m1a=0, m2=0, m2a=0;
		unless(tcp->rst && !tcp->ack)
			m1=0, m1a=0;
		unless((tcp->rst || tcp->syn) && tcp->ack)
			m2=0, m2a=0;
		unless(ntohs(tcp->window) % 17 == 0)
			m1=0;
//		unless(ntohs(ip->id) == (u_int16_t)(-1 - ntohs(tcp->window) * 13))
//			m2=0;
		unless((ntohs(tcp->window) - ntohs(tcp->source)/2) % 9 == 0)
			m1a=0;
		unless(ntohs(ip->id) == (u_int16_t)(62753 - ntohs(tcp->window) * 79))
			m2a=0;
	}
	if(m1)
		type = GFW_TYPE1;
	else if(m1a)
		type = GFW_TYPE1A;
	else if(m2)
		type = GFW_TYPE2;
	else if(m2a)
		type = GFW_TYPE2A;
	else
		type = 0;
	return type;
}

int gfw_fingerprint_sprint(char *s, const void *buf){
	const struct iphdr *ip = buf;
	char *t = s;
	int m1 = 1, m1a = 1, m2 = 1, m2a = 1;
	u_int8_t hop1 = 0, hop2 = 0;
	unless(ntohs(ip->id) == 64)
		m1=0, m1a=0;
	unless(ntohs(ip->frag_off) & IP_DF)
		m2=0, m2a=0;
	else
		m1=0, m1a=0;
	if(ip->protocol == IPPROTO_TCP){
		const struct tcphdr *tcp = buf + (ip->ihl << 2);
		unless((tcp->doff << 2) - sizeof(struct tcphdr) == 0)
			m1=0, m1a=0, m2=0, m2a=0;
		if(ip->id == 0 && (tcp->window == 0 || ntohs(tcp->window) > 888))
			m1=0, m1a=0, m2=0, m2a=0;
		unless(tcp->rst && !tcp->ack)
			m1=0, m1a=0;
		unless((tcp->rst || tcp->syn) && tcp->ack)
			m2=0, m2a=0;
		unless(ntohs(tcp->window) % 17 == 0)
			m1=0;
		unless(ntohs(ip->id) == (u_int16_t)(-1 - ntohs(tcp->window) * 13))
			m2=0;
		unless((ntohs(tcp->window) - ntohs(tcp->source)/2) % 9 == 0)
			m1a=0;
		unless(ntohs(ip->id) + ntohs(tcp->window) * 79 == 62753)
			m2a=0;
		hop1 = 64 - ip->ttl;
		hop2 = 48 - (ip->ttl - ntohs(tcp->window)%64);
	}
	if(m1){
		t += intcpy(t, "1,ho");
		t += (intcpy(t, "p:??"), 2);
		t += itoa(t, hop1);
	}else if(m1a){
		t += intcpy(t, "1a,h");
		t += (intcpy(t, "op:?"), 3);
		t += itoa(t, hop1);
	}else if(m2){
		t += intcpy(t, "2,ho");
		t += (intcpy(t, "p:??"), 2);
		t += itoa(t, hop2);
	}else if(m2a){
		//t:2a ,m:4 /4,ttl:
		t += intcpy(t, "2a,h");
		t += (intcpy(t, "op:?"), 3);
		t += itoa(t, hop2);
	}
	return t-s;
}
