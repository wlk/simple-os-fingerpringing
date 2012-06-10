#pragma once
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <string>
/// For winsock
#pragma comment(lib,"ws2_32.lib") 
/// this removes the need of mstcpip.h
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) 

class CMySocket
{
public:
	SOCKET sniffer;
	struct in_addr addr;
	struct hostent *local;
	struct sockaddr_in source,dest;
	WSADATA wsaData;
	// true - error; false - no error
	bool error;			
	char hostname[100];
	int in;

public:
	CMySocket(void);
	~CMySocket(void);
	bool sniffing(void);
};

