#pragma once
/// IP header
typedef struct ip_hdr
{
	/* 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)*/
    unsigned char ip_header_len:4; 
	/// 4-bit IPv4 version
    unsigned char ip_version :4; 
	/// IP type of service
    unsigned char ip_tos; 
	/// Total length
    unsigned short ip_total_length;
	/// Unique identifier
    unsigned short ip_id; 
	/// Fragment offset field
    unsigned char ip_frag_offset :5; 
    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;
	/// fragment offset
    unsigned char ip_frag_offset1; 
	/// Time to live
    unsigned char ip_ttl; 
	/// Protocol(TCP,UDP etc)
    unsigned char ip_protocol; 
	/// IP checksum
    unsigned short ip_checksum; 
	/// Source address
    unsigned int ip_srcaddr; 
	 /// Source address
    unsigned int ip_destaddr;
} IPV4_HDR;
/// UDP header
typedef struct udp_hdr
{
	/// Source port no.
    unsigned short source_port;
	/// Dest. port no.
    unsigned short dest_port; 
	/// Udp packet length
    unsigned short udp_length; 
	/// Udp checksum (optional)
    unsigned short udp_checksum; 
} UDP_HDR;

/// TCP header
typedef struct tcp_header
{
	/// source port
    unsigned short source_port; 
	/// destination port
    unsigned short dest_port; 
	/// sequence number - 32 bits
    unsigned int sequence; 
	/// acknowledgement number - 32 bits
    unsigned int acknowledge; 
	/// Nonce Sum Flag Added in RFC 3540.
    unsigned char ns :1; 
	/// according to rfc
    unsigned char reserved_part1:3; 

    /*The number of 32-bit words in the TCP header.
    This indicates where the data begins.
    The length of the TCP header is always a multiple
    of 32 bits.*/
	unsigned char data_offset:4;
	/// inish Flag
    unsigned char fin :1;
	/// Synchronise Flag
    unsigned char syn :1;
	/// Reset Flag
    unsigned char rst :1; 
	/// Push Flag
    unsigned char psh :1; 
	/// Acknowledgement Flag
    unsigned char ack :1; 
	/// Urgent Flag
    unsigned char urg :1; 
	/// ECN-Echo Flag
    unsigned char ecn :1; 
	/// Congestion Window Reduced Flag
    unsigned char cwr :1; 
    ////////////////////////////////
	/// window
    unsigned short window;
	/// checksum
    unsigned short checksum; 
	/// urgent pointer
    unsigned short urgent_pointer; 
} TCP_HDR;

/// ICMP header
typedef struct icmp_hdr
{
	/// ICMP Error type
    unsigned char type;
	/// Type sub code
    unsigned char code; 
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HDR;