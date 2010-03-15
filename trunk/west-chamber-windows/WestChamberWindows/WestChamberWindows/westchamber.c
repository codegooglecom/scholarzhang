/*
WestChamber Windows
Elysion
March 14 2010
*/

#include "precomp.h"
#pragma hdrstop

unsigned short ntohs(unsigned short x)
{
        unsigned char *s = (unsigned char *) &x;
        return (unsigned short)(s[0] << 8 | s[1]);
}
unsigned short htons(unsigned short x)
{
        unsigned char *s = (unsigned char *) &x;
        return (unsigned short)(s[0] << 8 | s[1]);
}
unsigned int htonl(unsigned int hostlong)
{
  return ((hostlong>>24) | ((hostlong&0xff0000)>>8) | ((hostlong&0xff00)<<8) | (hostlong<<24));
}
unsigned int ntohl(unsigned int hostlong)
{
  return ((hostlong>>24) | ((hostlong&0xff0000)>>8) | ((hostlong&0xff00)<<8) | (hostlong<<24));
}

//----------------------------------------------------------------------------------------------------

PUCHAR GetPacket(IN PNDIS_PACKET packet)		//Ref:http://www.cppblog.com/ay19880703/archive/2009/06/23/62233.html
{
NDIS_STATUS status ;
PNDIS_BUFFER NdisBuffer ;
UINT TotalPacketLength = 0 , copysize = 0 , DataOffset = 0 , PhysicalBufferCount  ,  BufferCount   ;
PUCHAR mybuffer = NULL ,tembuffer = NULL ;  
NDIS_PHYSICAL_ADDRESS HighestAcceptableMax={-1,-1};
pethheader eth;
NdisQueryPacket(packet,&PhysicalBufferCount,&BufferCount,&NdisBuffer,&TotalPacketLength);
status = NdisAllocateMemory( &mybuffer, 2048, 0, HighestAcceptableMax );
if( status != NDIS_STATUS_SUCCESS )
return NULL;
NdisZeroMemory( mybuffer, 2048 );
NdisQueryBufferSafe(NdisBuffer,&tembuffer,&copysize,NormalPagePriority);
NdisMoveMemory(mybuffer, tembuffer, copysize) ;
DataOffset = copysize ;
while(1)
{
NdisGetNextBuffer(NdisBuffer , &NdisBuffer ) ;
if( NdisBuffer == NULL )
break ;
NdisQueryBufferSafe(NdisBuffer,&tembuffer,&copysize,NormalPagePriority) ;
NdisMoveMemory( mybuffer + DataOffset , tembuffer, copysize) ;
DataOffset += copysize;
}
//KdPrint(("GetPacket -- length=%08x\n",DataOffset));
return mybuffer;
}

void DebugPrintPacket(PUCHAR packet,ULONG size)
{
	ULONG a=0;
	KdPrint(("Sending Packet: (length=%08x)",size));
	for(a=0;a<size;a++)
	{
		if(a%16==0) KdPrint(("\n"));
		KdPrint(("%02x ",packet[a]));
	}
	KdPrint(("\n"));
}

NDIS_STATUS														//Ref:http://www.cnblogs.com/xuneng/archive/2009/11/30/1613452.html
MySendPacket (
   NDIS_HANDLE     NdisBindingHandle,
   NDIS_HANDLE     NdisSendPacketPool,
   PVOID           pBuffer,
   ULONG           dwBufferLength
   )
{
   NDIS_STATUS     status;
   PNDIS_PACKET    pSendPacket = NULL;
   PNDIS_BUFFER    pSendPacketBuffer = NULL;
   PUCHAR          pSendBuffer = NULL;
   ULONG           dwSendBufferLength; 
   NDIS_PHYSICAL_ADDRESS HighestAcceptableAddress;
   PSEND_RSVD      SendRsvd = NULL;

   if (!NdisBindingHandle)
       return NDIS_STATUS_FAILURE;

   if (!pBuffer)
       return NDIS_STATUS_FAILURE;

   if (dwBufferLength > ETH_MAX_PACKET_SIZE)
       return NDIS_STATUS_FAILURE;

   HighestAcceptableAddress.QuadPart = -1;
   dwSendBufferLength = max(dwBufferLength, ETH_MIN_PACKET_SIZE);

   status = NdisAllocateMemory(&pSendBuffer, dwSendBufferLength, 0, HighestAcceptableAddress);
   if (status != NDIS_STATUS_SUCCESS)
   {
       return status;
   }

   RtlZeroMemory(pSendBuffer, dwSendBufferLength);
   RtlMoveMemory(pSendBuffer, pBuffer, dwSendBufferLength);

   NdisAllocatePacket(&status, &pSendPacket, NdisSendPacketPool);
   if (status != NDIS_STATUS_SUCCESS)
   {
       NdisFreeMemory(pSendBuffer, dwSendBufferLength, 0);
       
       return status;
   }

   NdisAllocateBuffer( &status, 
                       &pSendPacketBuffer, 
                       NdisSendPacketPool, 
                       pSendBuffer, 
                       dwSendBufferLength );
   if (status != NDIS_STATUS_SUCCESS)
   {
       NdisFreeMemory(pSendBuffer, dwSendBufferLength, 0);
       NdisDprFreePacket(pSendPacket);

       return status;
   }

   NdisChainBufferAtFront(pSendPacket, pSendPacketBuffer);

   SendRsvd = (PSEND_RSVD)(pSendPacket->ProtocolReserved); 
   SendRsvd->OriginalPkt = NULL;

   pSendPacket->Private.Head->Next=NULL; 
   pSendPacket->Private.Tail=NULL;

   NdisSetPacketFlags(pSendPacket, NDIS_FLAGS_DONT_LOOPBACK);

   NdisSend(&status, NdisBindingHandle, pSendPacket);
   if (status != STATUS_PENDING)
   {
       NdisUnchainBufferAtFront(pSendPacket ,&pSendPacketBuffer); 
       NdisQueryBufferSafe( pSendPacketBuffer, 
                            (PVOID *)&pSendBuffer, 
                            &dwSendBufferLength, 
                            HighPagePriority );
       NdisFreeBuffer(pSendPacketBuffer); 
       NdisFreeMemory(pSendBuffer, dwSendBufferLength, 0); 
       NdisDprFreePacket(pSendPacket);
   }

   return status;
}



//----------------------------------------------------------------------------------------------------

BOOLEAN IsUdpWithPortFiftyThree(PUCHAR pContent)
{
     return
		 (
		 pContent[12]==0x8 && pContent[13]==0x0			//IPv4
		 &&
		 pContent[23]==0x11                             //UDP
		 &&
		 pContent[34]==0 && pContent[35]==53            //Source Port:53
		 );
}


BOOLEAN IsTcpWithPortEighty(PUCHAR pContent)
{
	return
		 (
		 pContent[12]==0x8 && pContent[13]==0x0			//IPv4
		 &&
		 pContent[23]==0x06                             //TCP
		 &&
		 pContent[34]==0 && pContent[35]==80            //Source Port:80
		 );
}


BOOLEAN IsGFWPoisoned(PUCHAR data)
{
        unsigned short window;
        ptcpheader th;
        pudpheader uh;
        unsigned char* end;
        unsigned short* dns;
        unsigned int addr,ttl;
        unsigned short name;
    pipheader ip=(pipheader)(data+sizeof(ethheader));
    if(ip->frag_off&htons(0x1FFF)) return FALSE;
    if(ip->protocol==0x06)          //TCP
    {
                   th=(ptcpheader)(data+sizeof(ethheader)+sizeof(ipheader));
                   if(
						ip->tot_len <= sizeof(ipheader)
					   ||
					   ( th->doff*4 <sizeof(tcpheader) )
					   )
                   return FALSE;

                   if(
					   th->doff*4 != sizeof(tcpheader)
					   )
                   return FALSE;

                   window=ntohs(th->window); 
		           if (
					   ip->frag_off & htons(0x4000)	////IP_DF
					   )                             
                   {
			                        if (
										(
											(
											th->rst || th->syn
											)
										&&
										th->ack
										&&
										!th->fin
										&&
										ntohs(ip->id) == (unsigned short)(-1 - window * 13)
											)
									||
										ntohs(ip->id) == (unsigned short)(62753 - window * 79)
									)
				                    return TRUE; //type2[a]
                   }
                   else
                   {
                       			    if (
										(
										ip->id == htons(64)
										&&
										th->rst
										&&
										!th->ack
										&&
										!th->syn
										&&
										!th->fin
										&&
										window % 17 == 0
										)
									||
										(window - ntohs(th->source) / 2) % 9 == 0
									)
				                    return TRUE;//type1[a]
                   }
    }
    else if(ip->protocol==0x11)     //UDP
    {
                        uh=(pudpheader)(data+sizeof(ethheader)+sizeof(ipheader));
                        if(
							ip->tot_len<( sizeof(ethheader) + sizeof(ipheader) )
							||
							ntohs(uh->len) < sizeof(udpheader)
						)
                        return FALSE;

                        if (
							ip->frag_off & htons(0x4000)
							||
							ntohs(uh->len) < (sizeof(udpheader) + 12 + 16)
							)
                        return FALSE;

                        end=(unsigned char*)(uh+ntohs(uh->len));
                        dns=(unsigned short*)((char*)uh+sizeof(udpheader));

                        if(
							dns[2]!=htons(1)
							||
							dns[3]!=htons(1)
							||
							dns[4]!=0
							||
							dns[5]!=0
							||
							*(unsigned int*)(end-14) != htonl(0x00010001)
						)
                        return FALSE;
                        
                        addr=*(unsigned int*)(end-4);
                        ttl=*(unsigned int*)(end-10);
                        name=*(unsigned short*)(end-16);
                        
                        if (
							(
							ip->id == htons(0x7110)
							&&
							dns[1] == htons(0x8180)
							&&
							ttl == htonl(300)
							&&
							name == htons(0xc00c)
							)
                        ||
							(
							ntohs(ip->id) % 79 == 27
							&&
							dns[1] == htons(0x8580)
							&&
							ttl == htonl(86400)
							&&
							name != htons(0xc00c)
							)
						)
                        {
			               if (addr == htonl(0x5d2e0859)
			               || addr == htonl(0xcb620741)
			               || addr == htonl(0x0807c62d)
			               || addr == htonl(0x4e10310f)
			               || addr == htonl(0x2e52ae44)
			               || addr == htonl(0xf3b9bb27)
			               || addr == htonl(0x9f6a794b)
			               || addr == htonl(0x253d369e)
			               || addr == htonl(0x3b1803ad))
				           return TRUE;
                        }
    }
    return FALSE;
}
USHORT GetChecksum(PVOID buf,int size)					//Ref:http://hi.bccn.net/space-112902-do-blog-id-12121.html
{
	USHORT* buffer=(USHORT*)buf;
 unsigned long cksum=0;
 while(size>1)
 {
  cksum+=*buffer++;
  size-=sizeof(USHORT);
 }
 if(size)
 {
  cksum+=*(UCHAR *)buffer;
 }
 while (cksum>>16)
  cksum=(cksum>>16)+(cksum & 0xffff);
 return (USHORT)(~cksum);
}

USHORT GetTcpChecksum(PUCHAR packet)
{
	pipheader ip;
	ptcpheader tcp;
	ppseudo_header header;
	USHORT tcp_length;
	USHORT result;
	PUCHAR buffer;
	
	ip=(pipheader)(packet+sizeof(ethheader));
	tcp=(ptcpheader)(packet+sizeof(ethheader)+sizeof(ipheader));

	tcp_length=ntohs(ip->tot_len)-sizeof(ipheader);

	buffer=(PUCHAR)ExAllocatePool(NonPagedPool,sizeof(pseudo_header)+tcp_length);		//Allocated.

	header=(ppseudo_header)buffer;
	header->s_addr=ip->saddr;
	header->d_addr=ip->daddr;
	header->zero=0;
	header->protocol=0x06;	//TCP
	header->length=ntohs(tcp_length);

	RtlMoveMemory(buffer+sizeof(pseudo_header),tcp,tcp_length);
	result=GetChecksum(buffer,sizeof(pseudo_header)+tcp_length);
	
	ExFreePool(buffer);					//Released.
	return result;
}

void CodeZhang(PUCHAR packet,PADAPT adapter)
{
	pethheader eth;
	pipheader ip;
	ptcpheader tcp;
	ptcp_pack  sender,sender2;

	eth=(pethheader)packet;
	ip=(pipheader)(packet+sizeof(ethheader));
	tcp=(ptcpheader)(packet+sizeof(ethheader)+sizeof(ipheader));

	if(ip->frag_off&htons(0x1FFF)) return;
	if(
		ip->tot_len <= sizeof(ipheader)
		)
		return;
	if(
		!tcp->syn
		||
		!tcp->ack
		||
		tcp->rst
		||
		tcp->fin
	)
	return;
	if(GetTcpChecksum(packet))
		return;

	sender=(ptcp_pack)ExAllocatePool(NonPagedPool,sizeof(tcp_pack));		//Allocated.
	RtlZeroMemory(sender,sizeof(tcp_pack));

	//different from Linux environment, in NDIS we have to do all these things by ourself...
	RtlMoveMemory(sender->eth.ether_shost,eth->ether_dhost,6);
	RtlMoveMemory(sender->eth.ether_dhost,eth->ether_shost,6);
	sender->eth.ether_type=ntohs(0x0800);

	sender->ip.version=4;
	sender->ip.ihl=sizeof(ipheader)/4;
	//sender->ip.ihl_ver=0x45;
	sender->ip.tos=0;
	sender->ip.id=0;
	sender->ip.frag_off=htons(0x4000);
	sender->ip.protocol=0x06;
	
	sender->ip.saddr=ip->daddr;
	sender->ip.daddr=ip->saddr;
	
	sender->ip.tot_len=ntohs(sizeof(tcp_pack)-sizeof(ethheader));		//unnecessary in Linux, but vital in Windows.
	sender->ip.ttl=0xFF;	//let the packet survive as long as possible.
	sender->ip.check=GetChecksum(&sender->ip,sizeof(ipheader));

	sender->tcp.source=tcp->dest;
	sender->tcp.dest=tcp->source;
	sender->tcp.doff=sizeof(tcpheader)/4;
	//set_doff(sender->tcp.res1_doff,sizeof(tcpheader)/4);
	sender->tcp.window=0xFFFF;

	//essential part 1
	sender->tcp.fin=1;
	//set_fin(sender->tcp.flags,1);
	sender->tcp.seq=tcp->ack_seq;
	sender->tcp.ack_seq=tcp->seq;


	sender->tcp.check=GetTcpChecksum((PUCHAR)sender);
	
	sender2=(ptcp_pack)ExAllocatePool(NonPagedPool,sizeof(tcp_pack));	//Allocated.
	RtlMoveMemory(sender2,sender,sizeof(tcp_pack));						//copy it.

	//essential part 2
	sender2->tcp.fin=0;
	sender2->tcp.ack=1;

	//checksum calculation
	sender2->tcp.check=0;
	sender2->tcp.check=GetTcpChecksum((PUCHAR)sender2);
	
	//Sending Packets.	

	MySendPacket(adapter->BindingHandle,adapter->SendPacketPoolHandle,sender,sizeof(tcp_pack));
	MySendPacket(adapter->BindingHandle,adapter->SendPacketPoolHandle,sender2,sizeof(tcp_pack));

	//Release packets.
	ExFreePool(sender);
	ExFreePool(sender2);

	return;
}

BOOLEAN IsReceivedPacketInList(PUCHAR data)
{
	pipheader ip=(pipheader)(data+sizeof(ethheader));
	return IsInIpTable(ip->saddr);		//BIG_ENDIAN
}

BOOLEAN IsTcpSynAck(PUCHAR packet)
{
	ptcpheader tcp=(ptcpheader)(packet+sizeof(ethheader)+sizeof(ipheader));
	return(
		(tcp->syn)&&(tcp->ack)&&(!tcp->rst)&&(!tcp->fin)
		);
}

BOOLEAN IsIPVerFour(PUCHAR packet)
{
	pethheader eth=(pethheader)packet;
	return (eth->ether_type==ntohs(0x0800));	//IPv4 only.
}

BOOLEAN WestChamberReceiverMain(PNDIS_PACKET packet,PADAPT adapt)
//The return value indicates whether if we should let the packet pass.
{
	BOOLEAN result=TRUE,udp=FALSE,tcp=FALSE,gfw=FALSE,inlist=FALSE,sign=FALSE;
	PUCHAR pack=GetPacket(packet);
	if(pack==NULL) return TRUE;
	if(IsIPVerFour(pack))		//v4 supported only.
{

	udp=IsUdpWithPortFiftyThree(pack);
	tcp=IsTcpWithPortEighty(pack);

	if(udp || tcp)	gfw=IsGFWPoisoned(pack);
	if(tcp) sign=IsTcpSynAck(pack);
	if(sign) inlist=IsReceivedPacketInList(pack);

	if(gfw)
	{
		PrintLog("Detected GFW Poisoned Data -- ");
		if(udp)
		{
			PrintLog("Type=UDP, Port=53 (DNS data) -- dropped.\n");
			result=FALSE;
		}
		else PrintLog("Type=TCP, Port=80");
	}	

	if(inlist)
	{
		PrintLog(" -- In IP List -- CodeZhang Launched.\n");
		CodeZhang(pack,adapt);
	}
}
	NdisFreeMemory(pack,2048,0);
	return result;
}