#include "StdAfx.h"
#include "MySocket.h"
#include <iostream>

using namespace std;

CMySocket::CMySocket(void):
error(false)
{
	for(int x=0;x<100;x++)
		hostname[x] = 0;
	cout <<"Initialization...\n" << endl;
		if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
		error = true;
	else
	{
		sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
		if (sniffer == INVALID_SOCKET)
			error = true;
		else
		{
		if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
			 error = true;
		else{
			local = gethostbyname(hostname);
			if(local == NULL)
				error = true;		
			}
		}
	}
	
}


CMySocket::~CMySocket(void)
{
	 closesocket(sniffer);
	 WSACleanup();
}

/// Getting started
bool CMySocket::sniffing(void)
{
	for (int i = 0; local->h_addr_list[i] != 0; ++i)
    {
        memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		cout <<"Interface Number : "<< i <<" Address :"<< inet_ntoa(addr) << endl;
    }
    cout <<"Enter the interface you want to sniff : " << endl;
	// select interface to sniff
    cin >> in;
    memset(&dest, 0, sizeof(dest));
    memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    cout << "\nBinding socket to local system and port 0 ...";

    if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
    {
        cout << "bind(" << inet_ntoa(addr)  <<") failed."<< endl;
        return true;
    }
    cout <<"Binding successful";
    // Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)
    int j=1;
    cout <<"\nSetting socket to sniff...";
    if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
    {
        cout << "WSAIoctl() failed." <<endl;
        return true;
    }
    cout <<"Socket set.";
    // Begin sniffing
    cout << "\nStarted Sniffing" << endl;
    cout << "Statistics captured packets..." << endl;

	return false;
}
