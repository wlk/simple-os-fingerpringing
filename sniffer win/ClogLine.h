#pragma once
class ClogLine
{
public:
	unsigned char cIpSource[4];
	unsigned char cIpDest[4];
	unsigned char cTTL;
	unsigned int iPortSource;
	unsigned int iPortDest;
	int iProtocol;

public:
	ClogLine(void);
	~ClogLine(void);
	void GetValue(ClogLine line);
	void GetValue(const char *ipSource,const char *ipDest, int TTL,int Protocol,int S_Port,int D_Port);
	void UpdateTTL(int TTL);
};

