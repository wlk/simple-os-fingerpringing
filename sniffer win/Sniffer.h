#pragma once
#include "MySocket.h"
#include "ClogLine.h"
#include "Struktury.h"

class CSniffer
{
public:

	bool bError;
	CMySocket gniazdo;
	ClogLine *cLogLine;
	char *cBuffer;
	int mangobyte;
	unsigned int iCount;
	IPV4_HDR *iphdr;
	TCP_HDR *tcpheader;
	UDP_HDR *udpheader;
	ICMP_HDR *icmpheader;
public:
	int total,icmp,igmp,tcp,udp,others;

public:
	CSniffer(void);
	~CSniffer(void);
	bool StartSniffing(void);
	void PrintIcmpPacket(void);
	void PrintUdpPacket(void);
	void PrintTcpPacket(void);
	void PrintIpHeader(void);
	bool DodajLinie(const char *ipSource,const char *ipDest, int TTL,int Protocol,int S_Port,int D_Port);
	void SaveToFile();
};



