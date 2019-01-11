#ifndef TRACE_H
#define TRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct ethernet 
{
    char c;
}__attribute__((packed));

struct arp
{
    char c;
}__attribute__((packed));

struct ip
{/* 20 bytes min */
    uint8_t ver_IHL;           /* version(4) IHL(4) */
    uint8_t TOS;               /* DSCP(6) ECN(2) */
    uint16_t length;           /* header length (bytes) */
    uint16_t id;               
    uint16_t flags_frag;
    uint8_t TTL;               /* time to live */
    uint8_t protocol;          /* next protocol */
    uint16_t checksum;
    uint32_t src;              /* sender ip */
    uint32_t dst;              /* receiver ip */
    /* uint32_t options; */
}__attribute__((packed));

struct tcp
{
    char c;
}__attribute__((packed));

struct udp
{
    char c;
}__attribute__((packed));



#endif