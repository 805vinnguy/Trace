#include "trace.h"

int main(int argc, char* argv[]) 
{
    unsigned char frame_buf[PCAP_ERRBUF_SIZE];
    pcap_t* tracefile = NULL;
    struct pcap_pkthdr* pktheader = NULL;
    const u_char* pktdata = NULL;
    int pktnum = 0;
    struct ethernet* ethheader = NULL;
    /* struct arp* arpheader = NULL;
    struct ip* ipheader = NULL;
    struct tcp* tcpheader = NULL;
    struct udp* udpheader = NULL; */

    tracefile = pcap_open_offline(argv[1], (char*)frame_buf);
    if(tracefile == NULL) 
    {
        fprintf(stderr, "%s\n", frame_buf);
        exit(EXIT_FAILURE);
    }
    while(pcap_next_ex(tracefile, &pktheader, &pktdata) != -2)
    {
        pktnum++;
        print_pkthdr(pktnum, pktheader);
        ethheader = (struct ethernet*)(pktdata);
        
        print_ethhdr(ethheader);
    }

    pcap_close(tracefile);
    exit(EXIT_SUCCESS);
}

void print_pkthdr(int pktnum, struct pcap_pkthdr* pktheader) 
{
    uint32_t pktlen = (uint32_t)(pktheader->len);
    fprintf(stdout, "\nPacket number: %d  Packet Len: %u\n\n", pktnum, pktlen);
}

void print_ethhdr(struct ethernet* ethheader) 
{
    char* dst_str = ether_ntoa(&ethheader->dst);
    char* src_str = ether_ntoa(&ethheader->src);
    char* ether_type = determine_ether_type(ethheader->type);
    fprintf(stdout, "\tEthernet Header\n\t\tDest MAC: %s\n\t\tSource MAC: %s\n\t\tType: %s\n\n", 
                                            dst_str,          src_str,            ether_type);
}

char* determine_ether_type(uint16_t type_network) 
{
    /* convert type from network to host order */
    uint16_t type_host = ntohs(type_network);
    switch(type_host)
    {
        case ETHER_TYPE_IP:
            return "IP";
        case ETHER_TYPE_ARP:
            return "ARP";
        default:
            return "Unknown";
    }
}

void* safe_malloc(size_t size) 
{
    void* result = malloc(size);
    if(result == NULL) 
    {
        perror("safe_malloc failed! : ");
        exit(EXIT_FAILURE);
    }
    return result;
}