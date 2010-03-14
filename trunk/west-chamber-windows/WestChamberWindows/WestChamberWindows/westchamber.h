/*
WestChamber Windows
Elysion
March 14 2010
*/

#pragma once
#pragma pack(1)

//Structures

typedef struct ethhdr
{
unsigned char ether_dhost[6];
unsigned char ether_shost[6];
unsigned short ether_type;
}ethheader,*pethheader;

typedef struct iphdr
{
	//unsigned char ihl_ver;
	unsigned char ihl:4;
	unsigned char version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
} ipheader,*pipheader;

typedef struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
	//unsigned char res1_doff;
	//unsigned char flags;
	unsigned char res1:4;
	unsigned char doff:4;
	unsigned char fin:1;
	unsigned char syn:1;
	unsigned char rst:1;
	unsigned char psh:1;
	unsigned char ack:1;
	unsigned char urg:1;
	unsigned char res2:2;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
} tcpheader,*ptcpheader;

/*
#define get_doff(a) (a>>4)
#define set_doff(a,b) (a=((a&0x10)|(b<<4)))
#define get_fin(a) (a&0x1)
#define set_fin(a,b) (b==0)?(a&=0xFE):(a|=0x1)
#define get_syn(a) ((a&0x2)>>1)
#define set_syn(a,b) (b==0)?(a&=0xFD):(a|=0x2)
#define get_rst(a) ((a&0x4)>>2)
#define set_rst(a,b) (b==0)?(a&=0xFB):(a|=0x4)
#define get_psh(a) ((a&0x8)>>3)
#define set_psh(a,b) (b==0)?(a&=0xF7):(a|=0x8)
#define get_ack(a) ((a&0x10)>>4)
#define set_ack(a,b) (b==0)?(a&=0xEF):(a|=0x10)
*/

typedef struct udphdr
{
unsigned short source;
unsigned short dest;
unsigned short len;
unsigned short check;
} udpheader,*pudpheader;

typedef struct _psudo_tcp_udp_header
{
	unsigned int s_addr;
	unsigned int d_addr;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
} pseudo_header,*ppseudo_header;

typedef struct _tcp_pack
{
	ethheader eth;
	ipheader ip;
	tcpheader tcp;
} tcp_pack,*ptcp_pack;
//Functions and Macros

PUCHAR GetPacket(IN PNDIS_PACKET Packet);
BOOLEAN IsGFWPoisoned(PUCHAR data);
BOOLEAN IsUdpWithPortFiftyThree(PUCHAR pContent);
BOOLEAN IsReceivedPacketInList(PUCHAR data);
BOOLEAN IsIPVerFour(PUCHAR packet);
BOOLEAN WestChamberReceiverMain(PNDIS_PACKET packet,PADAPT adapt);
NDIS_STATUS MySendPacket(NDIS_HANDLE NdisBindingHandle,NDIS_HANDLE NdisSendPacketPool,PVOID pBuffer,ULONG dwBufferLength);
void DebugPrintPacket(PUCHAR packet,ULONG size);

//Some useful short functions copied from Linux SourceCode.

unsigned short ntohs(unsigned short x);
unsigned short htons(unsigned short x);
unsigned int htonl(unsigned int hostlong);
unsigned int ntohl(unsigned int hostlong);

#define PrintLog(a) KdPrint((a))

#define ETH_MAX_PACKET_SIZE 1500
#define ETH_MIN_PACKET_SIZE 60