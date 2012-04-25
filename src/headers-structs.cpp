struct ipheader {
 unsigned char         iph_ihl:4, ip_ver:4;
 unsigned char         iph_tos;
 unsigned short int    iph_len;
 unsigned short int    iph_ident;
 unsigned char         iph_flags;
 unsigned short int    iph_offset;
 unsigned char         iph_ttl;
 unsigned char         iph_protocol;
 unsigned short int    iph_chksum;
 unsigned int          iph_source;
 unsigned int          iph_dest;
};

struct icmpheader {
 unsigned char      icmph_type;
 unsigned char      icmph_code;
 unsigned short int icmph_chksum;
 /* The following data structures are ICMP type specific */
 unsigned short int icmph_ident;
 unsigned short int icmph_seqnum;
}; /* total ICMP header length: 8 bytes (= 64 bits) */

struct udpheader {
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
}; /* total udp header length: 8 bytes (= 64 bits) */

struct tcpheader {
 unsigned short int   tcph_srcport;
 unsigned short int   tcph_destport;
 unsigned int     tcph_seqnum;
 unsigned int     tcph_acknum;
 unsigned char    tcph_reserved:4, tcph_offset:4;
 unsigned char    tcph_flags;
 unsigned short int   tcph_win;
 unsigned short int   tcph_chksum;
 unsigned short int   tcph_urgptr;
};
/* total tcp header length: 20 bytes (= 160 bits) */
