#include "StdAfx.h"
#include "Sniffer.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <errno.h>
#define NUM 1000 // liczba analizowanych paczek

using namespace std;

CSniffer::CSniffer(void):
bError(false)
,total(0)
,icmp(0)
,igmp(0)
,tcp(0)
,udp(0)
,others(0)
,cLogLine(NULL)
,iCount(0)
{
	cBuffer = new char[65536];
	if(cBuffer == NULL)
		bError = true;
}


CSniffer::~CSniffer(void)
{
	
	delete cBuffer;
	delete [] cLogLine;
}


bool CSniffer::StartSniffing(void)
{
	int z=0;
	if(bError)
		return true;
	gniazdo.sniffing();
		
	 do
    {
		mangobyte = recvfrom(gniazdo.sniffer, cBuffer , 65536 , 0 , 0 , 0); //Eat as much as u can
        if(mangobyte > 0)
		{
			 iphdr = (IPV4_HDR *)cBuffer;
			 ++total;

	 		switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
		 	{
				case 1: // ICMP Protocol
					++icmp;
					PrintIcmpPacket();
					break;
				case 2: // IGMP Protocol
					++igmp;
					break;
				case 6: // TCP Protocol
					++tcp;
					PrintTcpPacket();
					break;

				case 17: // UDP Protocol
					++udp;
					PrintUdpPacket();
				break;

				default: // Some Other Protocol like ARP etc.
					++others;
					break;
			}
			printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d Unikat: %d\r",tcp,udp,icmp,igmp,others,total,iCount);
		}
        else
            perror( "recvfrom() failed.\n");
		z++;
    }
    while (mangobyte > 0 && z < NUM );
	SaveToFile();
	return false;
}



void CSniffer::PrintIcmpPacket(void)
{
	PrintIpHeader();
}


void CSniffer::PrintUdpPacket(void)
{
	unsigned short iphdrlen;

    iphdr = (IPV4_HDR *)cBuffer;
    iphdrlen = iphdr->ip_header_len*4;
	udpheader = (UDP_HDR *)(cBuffer + iphdrlen);

    memset(&gniazdo.source, 0, sizeof(gniazdo.source));
    gniazdo.source.sin_addr.s_addr = iphdr->ip_srcaddr;
    memset(&gniazdo.dest, 0, sizeof(gniazdo.dest));
    gniazdo.dest.sin_addr.s_addr = iphdr->ip_destaddr;
	// IP SOURCE
	string source = inet_ntoa(gniazdo.source.sin_addr);
	// IP DEST
	string dest =  inet_ntoa(gniazdo.dest.sin_addr);
	int D_PORT = udpheader->dest_port;
	DodajLinie(source.c_str(),dest.c_str(),static_cast<unsigned int>(iphdr->ip_ttl),iphdr->ip_protocol,udpheader->source_port,D_PORT);

}


void CSniffer::PrintTcpPacket(void)
{
	unsigned short iphdrlen;

    iphdr = (IPV4_HDR *)cBuffer;
    iphdrlen = iphdr->ip_header_len*4;
	tcpheader=(TCP_HDR*)(cBuffer+iphdrlen);

    memset(&gniazdo.source, 0, sizeof(gniazdo.source));
    gniazdo.source.sin_addr.s_addr = iphdr->ip_srcaddr;
    memset(&gniazdo.dest, 0, sizeof(gniazdo.dest));
    gniazdo.dest.sin_addr.s_addr = iphdr->ip_destaddr;
	string source = inet_ntoa(gniazdo.source.sin_addr);
	string dest =  inet_ntoa(gniazdo.dest.sin_addr);
	DodajLinie(source.c_str(),dest.c_str(),static_cast<unsigned int>(iphdr->ip_ttl),iphdr->ip_protocol,ntohs(tcpheader->source_port),ntohs(tcpheader->dest_port));


}


void CSniffer::PrintIpHeader(void)
{
	unsigned short iphdrlen;

    iphdr = (IPV4_HDR *)cBuffer;
    iphdrlen = iphdr->ip_header_len*4;
	
    memset(&gniazdo.source, 0, sizeof(gniazdo.source));
    gniazdo.source.sin_addr.s_addr = iphdr->ip_srcaddr;
    memset(&gniazdo.dest, 0, sizeof(gniazdo.dest));
    gniazdo.dest.sin_addr.s_addr = iphdr->ip_destaddr;
	string source = inet_ntoa(gniazdo.source.sin_addr);
	string dest =  inet_ntoa(gniazdo.dest.sin_addr);
	DodajLinie(source.c_str(),dest.c_str(),static_cast<unsigned int>(iphdr->ip_ttl),iphdr->ip_protocol,0,0);
	
}

bool CSniffer::DodajLinie(const char *ipSource,const char *ipDest, int TTL,int Protocol,int S_Port,int D_Port )
{
	ClogLine *buf;

	if(iCount > 0)
	{
		buf = new ClogLine[2];
		buf[0].GetValue(ipSource,ipDest,TTL,Protocol,S_Port,D_Port);
		for(int x=0; x<static_cast<int>(iCount); x++)
		{
			if( (buf[0].cIpSource[0] == cLogLine[x].cIpSource[0] && buf[0].cIpSource[1] == cLogLine[x].cIpSource[1] && buf[0].cIpSource[2] == cLogLine[x].cIpSource[2] && buf[0].cIpSource[3] == cLogLine[x].cIpSource[3])\
				&& (buf[0].cIpDest[0] == cLogLine[x].cIpDest[0] && buf[0].cIpDest[1] == cLogLine[x].cIpDest[1] && buf[0].cIpDest[2] == cLogLine[x].cIpDest[2] && buf[0].cIpDest[3] == cLogLine[x].cIpDest[3]) )
			{
				cLogLine[x].UpdateTTL(TTL);
				return true;
			}
		}
	}
	if(cLogLine == NULL)
	{
		cLogLine = new ClogLine[2];
		iCount++;
		cLogLine[0].GetValue(ipSource,ipDest,TTL,Protocol,S_Port,D_Port);
	}		
	else
	{
		// Copying data to a temporary buffer
		buf = new ClogLine [iCount+1];
		for(int x=0; x<static_cast<int>(iCount); x++)
			buf[x].GetValue(cLogLine[x]);
		// An increase of one of the stored data
		iCount++;
		// Reallocation of memory//////////////////////
		delete [] cLogLine;
		cLogLine = new ClogLine [iCount+1];
		// Entering the old values ////////////////
		for(int x=0; x<static_cast<int>(iCount); x++)
			cLogLine[x].GetValue(buf[x]);
		// Entering a new value ////////////////
		cLogLine[iCount-1].GetValue(ipSource,ipDest,TTL,Protocol,S_Port,D_Port);
		
	}
	return false;
}

void CSniffer::SaveToFile()
{
	bool otwarty;
	ofstream plik;
	plik.open("log.txt");
	otwarty = plik.is_open();
	for(int x=0;x < static_cast<int>(iCount); x++)
	{	// Source IP
		plik << static_cast<int>(cLogLine[x].cIpSource[0]) <<"."<<static_cast<int>(cLogLine[x].cIpSource[1])<<".";
		plik << static_cast<int>(cLogLine[x].cIpSource[2]) <<"."<<static_cast<int>(cLogLine[x].cIpSource[3])<<"\t";
		// Dest IP
		plik << static_cast<int>(cLogLine[x].cIpDest[0]) <<"."<<static_cast<int>(cLogLine[x].cIpDest[1])<<".";
		plik << static_cast<int>(cLogLine[x].cIpDest[2]) <<"."<<static_cast<int>(cLogLine[x].cIpDest[3])<<"\t";
		// TTL
		plik << static_cast<int>(cLogLine[x].cTTL) << "\t";
		// SOURCE PORT
		plik << cLogLine[x].iPortSource << "\t";
		// DESTINATION PORT
		plik << cLogLine[x].iPortDest << "\t";
		// TYP (UDP, TCP itp.)
		if( cLogLine[x].iProtocol == 1)
			plik << "ICMP" << endl;
		if( cLogLine[x].iProtocol == 2)
			plik << "IGMP" << endl;
		if( cLogLine[x].iProtocol == 6)
			plik << "TCP" << endl;
		if( cLogLine[x].iProtocol == 17)
			plik << "UDP" << endl;
	}
	plik.close();
}