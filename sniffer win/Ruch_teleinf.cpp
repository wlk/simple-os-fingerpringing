///* Ruch_teleinf.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Sniffer.h"


int _tmain(int argc, _TCHAR* argv[])
{
	CSniffer sniff;
	sniff.StartSniffing();
	system("pause");
	return 0;
}

