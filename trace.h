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

struct ethernet 
{/* 14 bytes */
    struct ether_addr dst;     /* destination MAC */
    struct ether_addr src;     /* source MAC */
    uint16_t type;             /* next protocol */
}__attribute__((packed));

struct arp
{/* 28 bytes */
    uint16_t htype;            /* hardware type */
    uint16_t ptype;            /* protocol type */
    uint8_t hLen;              /* hardware address length */
    uint8_t pLen;              /* protocol address length */
    uint16_t oper;             /* operation */
    uint8_t sha[6];            /* sender hardware address */
    uint8_t spa[4];            /* sender protocol address */
    uint8_t tha[6];            /* target hardware address */
    uint8_t tpa[4];            /* target protocol address */
}__attribute__((packed));

struct ip
{/* 20 bytes min */
    uint8_t ver_IHL;           /* version(4) IHL(4) */
    uint8_t TOS;               /* DSCP(6) ECN(2) */
    uint16_t length;           /* length header + data (bytes) */
    uint16_t id;               
    uint16_t flags_frag;
    uint8_t TTL;               /* time to live */
    uint8_t next_protocol;
    uint16_t checksum;
    uint32_t src;              /* sender ip */
    uint32_t dst;              /* receiver ip */
    /* uint32_t options; */
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

void print_pkthdr(int pktnum, struct pcap_pkthdr* pktheader);
void print_ethhdr(struct ethernet* ethheader);
    char* determine_ether_type(uint16_t type_network);

void* safe_malloc(size_t size);

#endif