#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <unistd.h>

void process_packet(unsigned char *, int);
void print_tcp_packet(unsigned char* , int);
void print_ip_header(unsigned char* , int);


FILE *logfile;
int total_packets = 0;
int tcp_count = 0;
int data_size;
unsigned int saddr_size;
struct sockaddr saddr;
struct in_addr in;
unsigned char buffer[8192 * 2];
int fd;
struct sockaddr_in source, dest;

int main(int argc, char *argv[]) {

	if (getuid() != 0) {
		fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
		exit(EXIT_FAILURE);
	}


	logfile=fopen("log.txt","a");
	if(logfile==NULL) printf("Unable to create file.");




	fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); //przerobić żeby było TCP i UDP
	if(fd < 0){
		printf("Socket creation errro");
		return 1;
	}

	while(true){
		saddr_size = sizeof saddr;
		int data_size = recvfrom(fd, buffer, 65536, 0, &saddr, &saddr_size);
		if(data_size < 0 ){
			printf("recvfrom failed to get packet\n");
			return 1;
		}
		else{
			process_packet(buffer, data_size);
		}
	}
}

void process_packet(unsigned char * buffer, int size){
	++total_packets;
	printf("total packets: %d\n", total_packets);
	struct iphdr *iph = (struct iphdr*)buffer;
	switch(iph->protocol){
	case 6:
		++tcp_count;
		print_tcp_packet(buffer , size);
		break;
	}
}

void print_ip_header(unsigned char* buffer, int size){
	unsigned short ip_header_length;
	
	struct ethhdr *ethernet_header;
	struct tcphdr *tcp_header;
	struct iphdr *iph = (struct iphdr *)buffer;
	
	ip_header_length =iph->ihl*4;
	tcp_header = (struct tcphdr*) (buffer + sizeof(struct ethhdr)+ ip_header->ihl * 4); // Do sprawdzenia

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	//IP Version        : %d\n",(unsigned int)iph->version
	//IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4
	//Type Of Service   : %d\n",(unsigned int)iph->tos
	//IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len)
	//Identification    : %d\n",ntohs(iph->id)
	//Protocol : %d\n",(unsigned int)iph->protocol
	//Checksum : %d\n",ntohs(iph->check)

	//dodać żeby logował S_PORT, D_PORT, PROTOCOL
	fprintf(logfile, "%s\t%s\t%d\n", inet_ntoa(source.sin_addr), inet_ntop(dest.sin_addr), (unsigned int)iph->ttl);



}

void print_tcp_packet(unsigned char* buffer, int size){
	print_ip_header(buffer, size);
}


