#ifndef TRACE_H
#define TRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "checksum.h"

struct ethernet 
{/* 14 bytes */
    struct ether_addr dst;     /* destination MAC */
    struct ether_addr src;     /* source MAC */
    uint16_t type;             /* next protocol */
}__attribute__((packed));

/* 
    Defined in <net/ethernet.h>
    struct ether_addr
    {
        uint8_t ether_addr_octet[6];
    };
*/

struct arp
{/* 28 bytes */
    uint16_t htype;            /* hardware type */
    uint16_t ptype;            /* protocol type */
    uint8_t hLen;              /* hardware address length */
    uint8_t pLen;              /* protocol address length */
    uint16_t oper;             /* operation */
    struct ether_addr sha;     /* sender hardware address */
    struct in_addr spa;        /* sender protocol address */
    struct ether_addr tha;     /* target hardware address */
    struct in_addr tpa;        /* target protocol address */
}__attribute__((packed));

/* 
    Defined in <netinet/in.h>
    typedef uint32_t in_addr_t
    struct in_addr
    {
        in_addr_t s_addr;
    };
*/

struct ip
{/* 20 bytes min */
    uint8_t ver_IHL;           /* version(4) IHL(4) */
    uint8_t TOS;               /* DSCP(6) ECN(2) */
    uint16_t length;           /* length header + data (bytes) */
    uint16_t id;               
    uint16_t flags_frag;
    uint8_t TTL;               /* time to live */
    uint8_t protocol;          /* next protocol */
    uint16_t checksum;
    struct in_addr src;        /* sender ip */
    struct in_addr dst;        /* receiver ip */
    /* uint32_t options; */
}__attribute__((packed));

struct icmp
{/* 8 bytes */
    uint8_t type;              /* ICMP type */
    uint8_t code;              /* ICMP subtype */
    uint16_t checksum;
    uint32_t rest_of_header;   /* based on type and subtype */
}__attribute__((packed));

struct tcp
{/* 20 bytes min */
    uint16_t src_port;         /* sending port */
    uint16_t dst_port;         /* receiving port */
    uint32_t sequence;         /* sequence number */
    uint32_t ack;              /* acknowledgment number */
    uint16_t offset_res_flags; /* data offset(4) reserved(3) flags(9) */
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urg;              /* urgent pointer */
    /* uint32_t options; */
}__attribute__((packed));

struct tcp_pseudo
{/* 32 bytes min */
    struct in_addr src;        /* sender ip */
    struct in_addr dst;        /* receiver ip */
    uint8_t zeros;
    uint8_t protocol;          /* TCP (0x06) */
    uint16_t tcp_len;          /* length of TCP header + data */
    struct tcp header;         /* TCP header */
}__attribute__((packed));

struct udp
{/* 8 bytes */
    uint16_t src_port;         /* sending port */
    uint16_t dst_port;         /* destination port */
    uint16_t length;           /* UDP header + data (bytes) */
    uint16_t checksum;
}__attribute__((packed));

#define ETH_SIZE 14
#define ARP_SIZE 28
#define IP_SIZE_MIN 20
#define TCP_SIZE_MIN 20
#define UDP_SIZE 8

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806

#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

#define IP_IHL_MASK 0x000F
#define IP_ECN_MASK 0x0003
#define IP_PROTO_ICMP 0x01
#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11
#define WORD_LEN 4

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0

#define PORT_DNS 53
#define PORT_HTTP 80
#define PORT_TELNET 23
#define PORT_FTP 21
#define PORT_POP3 110
#define PORT_SMTP 25

#define TCP_FLAG_MASK_SYN 0x02
#define TCP_FLAG_MASK_RST 0x04
#define TCP_FLAG_MASK_FIN 0x01
#define TCP_FLAG_MASK_ACK 0x10

void print_pkthdr(int pktnum, struct pcap_pkthdr* pktheader);
void print_ethhdr(struct ethernet* ethheader);
    char* determine_ether_type(uint16_t type_network);
void print_ether_type(uint16_t type, const u_char* pktdata);
    void print_arphdr(struct arp* arpheader);
        char* determine_arp_oper(uint16_t oper_network);
    void print_iphdr(struct ip* ipheader);
        char* determine_ip_protocol(uint8_t protocol);
void print_ip_protocol(uint8_t protocol, const u_char* pktdata, uint8_t IHL);
    void print_icmphdr(struct icmp* icmpheader);
    void print_tcphdr(struct tcp* tcpheader);
        char* get_flags(uint16_t offset_res_flags);
    void print_udphdr(struct udp* udpheader);
        char* determine_port(uint16_t port_network);

char* safe_sprintf(char* str, uint16_t num);
void* safe_malloc(size_t size);

#endif