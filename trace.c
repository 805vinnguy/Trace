#include "trace.h"

int main(int argc, char* argv[]) 
{
    unsigned char frame_buf[PCAP_ERRBUF_SIZE];
    pcap_t* tracefile = NULL;
    struct pcap_pkthdr* pktheader = NULL;
    const u_char* pktdata = NULL;
    int pktnum = 0;
    struct ethernet* ethheader = NULL;
    struct arp* arpheader = NULL;
    struct ip* ipheader = NULL;
    /* struct tcp* tcpheader = NULL;
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
        switch(ntohs(ethheader->type))
        {
            case ETHER_TYPE_ARP:
                arpheader = (struct arp*)(pktdata + ETH_SIZE);
                print_arphdr(arpheader);
            case ETHER_TYPE_IP:
                ipheader = (struct ip*)(pktdata + ETH_SIZE);
                print_iphdr(ipheader);
            default:
                continue;
        }
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
    /* mac format buffer for dst and src */
    char* mac_format = NULL; 
    char* ether_type = determine_ether_type(ethheader->type);
    mac_format = ether_ntoa(&ethheader->dst);
    fprintf(stdout, "\tEthernet Header\n\t\tDest MAC: %s\n", mac_format);
    mac_format = ether_ntoa(&ethheader->src);
    fprintf(stdout, "\t\tSource MAC: %s\n\t\tType: %s\n\n", mac_format, ether_type);
}

char* determine_ether_type(uint16_t type_network) 
{
    /* convert type from network to host order */
    uint16_t type_host = ntohs(type_network);
    switch(type_host)
    {
        case ETHER_TYPE_ARP:
            return "ARP";
        case ETHER_TYPE_IP:
            return "IP";
        default:
            return "Unknown";
    }
}

void print_arphdr(struct arp* arpheader)
{
    char* oper = determine_arp_oper(arpheader->oper);
    /* mac format buffer for sha and tha*/
    char* mac_format = NULL;
    /* ip format buffer for spa and tpa */
    char* ip_format = NULL;
    mac_format = ether_ntoa(&arpheader->sha);
    ip_format = inet_ntoa(arpheader->spa);
    fprintf(stdout, "\tARP header\n\t\tOpcode: %s\n\t\tSender MAC: %s\n\t\tSender IP: %s\n",
                                       oper,           mac_format,         ip_format);
    mac_format = ether_ntoa(&arpheader->tha);
    ip_format = inet_ntoa(arpheader->tpa);
    fprintf(stdout, "\t\tTarget MAC: %s\n\t\tTarget IP: %s\n\n", 
                         mac_format,         ip_format);
}

char* determine_arp_oper(uint16_t oper_network) 
{
    uint16_t oper_host = ntohs(oper_network);
    switch(oper_host)
    {
        case ARP_REQUEST:
            return "Request";
        case ARP_REPLY:
            return "Reply";
        default:
            return "Unknown";
    }
}

void print_iphdr(struct ip* ipheader)
{
    
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