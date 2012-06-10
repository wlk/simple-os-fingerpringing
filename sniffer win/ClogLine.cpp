#include "StdAfx.h"
#include "ClogLine.h"
#include <string>

ClogLine::ClogLine(void):
cTTL(0)
,iPortSource(1)
,iPortDest(1)
,iProtocol(2)
{
}


ClogLine::~ClogLine(void)
{
}

void ClogLine::GetValue(ClogLine line)
{
	for(int x=0;x<4;x++)
	{
		cIpSource[x] = line.cIpSource[x];
		cIpDest[x] = line.cIpDest[x];
	}
	cTTL = line.cTTL;
	iProtocol = line.iProtocol;
	iPortSource =line.iPortSource;
	iPortDest = line.iPortDest;

}

void ClogLine::GetValue(const char *ipSource,const char *ipDest, int TTL,int Protocol,int S_Port,int D_Port)
{
	int y=1,buf;
	buf = atoi(ipSource);
	cIpSource[0] = buf;
	buf = atoi(ipDest);
	cIpDest[0] = buf;
	for(int x=0; x< strlen(ipSource) && y <4; x++)
	{
		if(ipSource[x] == '.')
		{cIpSource[y] = atoi(ipSource+x+1); y++;}
	}
	y=1;
	for(int x=0; x< strlen(ipDest) && y <4; x++)
	{
		if(ipDest[x] == '.')
		{cIpDest[y] = atoi(ipDest+x+1); y++;}
	}
	cTTL = TTL;
	iProtocol = Protocol;
	iPortSource = S_Port;
	iPortDest = D_Port;
}
void ClogLine::UpdateTTL(int TTL)
{
	if(cTTL < TTL) cTTL = TTL; 
}