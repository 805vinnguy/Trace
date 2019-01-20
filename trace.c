#include "trace.h"

int main(int argc, char* argv[]) 
{
    unsigned char frame_buf[PCAP_ERRBUF_SIZE];
    pcap_t* tracefile = NULL;

    if(argc < 2)
        usage();
    tracefile = pcap_open_offline(argv[1], (char*)frame_buf);
    if(tracefile == NULL) 
    {
        fprintf(stderr, "%s\n", frame_buf);
        usage();
    }
    print_packets(tracefile);
    pcap_close(tracefile);
    exit(EXIT_SUCCESS);
}

void usage(void)
{
    fprintf(stderr, "Usage: ./trace filepath [.pcap]\n");
    exit(EXIT_FAILURE);
}

void print_packets(pcap_t* tracefile)
{
    struct pcap_pkthdr* pktheader = NULL;
    const u_char* pktdata = NULL;
    int pktnum = 0;
    struct ethernet* ethheader = NULL;
    while(pcap_next_ex(tracefile, &pktheader, &pktdata) != -2)
    {
        pktnum++;
        print_pkthdr(pktnum, pktheader);
        ethheader = (struct ethernet*)(pktdata);
        print_ethhdr(ethheader);
        print_ether_type(ethheader->type, pktdata);
    }
}

void print_pkthdr(int pktnum, struct pcap_pkthdr* pktheader) 
{
    uint32_t pktlen = (uint32_t)(pktheader->len);
    fprintf(stdout, "\nPacket number: %d  Packet Len: %u\n\n", pktnum, pktlen);
}

void print_ethhdr(struct ethernet* ethheader) 
{
    char* mac_format = NULL; 
    char* ether_type = determine_ether_type(ethheader->type);
    mac_format = ether_ntoa(&ethheader->dst);
    fprintf(stdout, "\tEthernet Header\n\t\tDest MAC: %s\n", mac_format);
    mac_format = ether_ntoa(&ethheader->src);
    fprintf(stdout, "\t\tSource MAC: %s\n\t\tType: %s\n\n", 
                    mac_format, ether_type);
}

char* determine_ether_type(uint16_t type_network) 
{
    uint16_t type_host = ntohs(type_network);
    if(type_host == ETHER_TYPE_ARP)
        return "ARP";
    else if(type_host == ETHER_TYPE_IP)
        return "IP";
    else
        return "Unknown";
}

void print_ether_type(uint16_t type, const u_char* pktdata)
{
    struct arp* arpheader = NULL;
    struct ip* ipheader = NULL;
    switch(ntohs(type))
    {
        case ETHER_TYPE_ARP:
            arpheader = (struct arp*)(pktdata + ETH_SIZE);
            print_arphdr(arpheader);
            break;
        case ETHER_TYPE_IP:
            ipheader = (struct ip*)(pktdata + ETH_SIZE);
            print_iphdr(ipheader);
            print_ip_protocol(ipheader, pktdata);
            break;
        default:
            break;
    }
}

void print_arphdr(struct arp* arpheader)
{
    char* oper = determine_arp_oper(arpheader->oper);
    char* mac_format = NULL;
    char* ip_format = NULL;
    mac_format = ether_ntoa(&arpheader->sha);
    ip_format = inet_ntoa(arpheader->spa);
    fprintf(stdout, "\tARP header\n\t\tOpcode: %s\n\t\t"
                    "Sender MAC: %s\n\t\tSender IP: %s\n",
                    oper, mac_format, ip_format);
    mac_format = ether_ntoa(&arpheader->tha);
    ip_format = inet_ntoa(arpheader->tpa);
    fprintf(stdout, "\t\tTarget MAC: %s\n\t\tTarget IP: %s\n\n", 
                         mac_format,         ip_format);
}

char* determine_arp_oper(uint16_t oper_network) 
{
    uint16_t oper_host = ntohs(oper_network);
    if(oper_host == ARP_REQUEST)
        return "Request";
    else if(oper_host == ARP_REPLY)
        return "Reply";
    else
        return "Unknown";
}

void print_iphdr(struct ip* ipheader)
{
    uint8_t version = (ipheader->ver_IHL) >> 4;
    uint8_t IHL = (ipheader->ver_IHL) & IP_IHL_MASK;
    uint32_t header_len = IHL * WORD_LEN;
    uint8_t diffserv = (ipheader->TOS) >> 2;
    uint8_t ECN = (ipheader->TOS) & IP_ECN_MASK;
    char* protocol = determine_ip_protocol(ipheader->protocol);
    uint16_t checksum = in_cksum((unsigned short*)ipheader, header_len);
    char* check = (checksum == 0x0000) ? "Correct" : "Incorrect";
    char* ip_format = NULL;
    ip_format = inet_ntoa(ipheader->src);
    fprintf(stdout, "\tIP Header\n\t\tIP Version: %u\n\t\t"
         "Header Len (bytes): %u\n\t\tTOS subfields:\n\t\t"
         "   Diffserv bits: %u\n\t\t   ECN bits: %u\n\t\t"
         "TTL: %u\n\t\tProtocol: %s\n\t\t"
         "Checksum: %s (0x%04x)\n\t\tSender IP: %s\n", 
        version, header_len, diffserv, ECN, ipheader->TTL, 
        protocol, check, ntohs(ipheader->checksum), ip_format);
    ip_format = inet_ntoa(ipheader->dst);
    fprintf(stdout, "\t\tDest IP: %s\n", ip_format);
}

char* determine_ip_protocol(uint8_t protocol)
{
    if(protocol == IP_PROTO_ICMP)
        return "ICMP";
    else if(protocol == IP_PROTO_TCP)
        return "TCP";
    else if(protocol == IP_PROTO_UDP)
        return "UDP";
    else
        return "Unknown";
}

void print_ip_protocol(struct ip* ipheader, const u_char* pktdata)
{
    uint32_t ip_header_len = (ipheader->ver_IHL & IP_IHL_MASK) * WORD_LEN;
    struct icmp* icmpheader = NULL;
    struct tcp* tcpheader = NULL;
    struct udp* udpheader = NULL;
    switch(ipheader->protocol)
    {
        case IP_PROTO_ICMP:
            icmpheader = (struct icmp*)(pktdata + ETH_SIZE + ip_header_len);
            print_icmphdr(icmpheader);
            break;
        case IP_PROTO_TCP:
            tcpheader = (struct tcp*)(pktdata + ETH_SIZE + ip_header_len);
            print_tcphdr(tcpheader, ipheader);
            break;
        case IP_PROTO_UDP:
            udpheader = (struct udp*)(pktdata + ETH_SIZE + ip_header_len);
            print_udphdr(udpheader);
            break;
        default:
            break;
    }
}

void print_icmphdr(struct icmp* icmpheader)
{
    if(icmpheader->type == ICMP_ECHO_REQUEST)
        fprintf(stdout, "\n\tICMP Header\n\t\tType: %s\n", "Request");
    else if(icmpheader->type == ICMP_ECHO_REPLY)
        fprintf(stdout, "\n\tICMP Header\n\t\tType: %s\n", "Reply");
    else
        fprintf(stdout, "\n\tICMP Header\n\t\tType: %u\n", icmpheader->type);
}

void print_tcphdr(struct tcp* tcpheader, struct ip* ipheader)
{
    char* src_port = determine_port(tcpheader->src_port);
    char* dst_port = determine_port(tcpheader->dst_port);
    uint16_t offset_host = (ntohs(tcpheader->offset_res_flags) >> 12)*WORD_LEN;
    char* flagstr = get_flags(ntohs(tcpheader->offset_res_flags));
    struct tcp_pseudo* pseudo = get_tcp_pseudo(tcpheader, ipheader);
    uint16_t checksum = in_cksum((unsigned short*)pseudo, 
                        ntohs(pseudo->tcp_len) + TCP_PSEUDO_LEN);
    char* check = (checksum == 0x0000) ? "Correct" : "Incorrect";
    fprintf(stdout, "\n\tTCP Header\n\t\tSource Port:  %s\n\t\t"
                    "Dest Port:  %s\n\t\tSequence Number: %u\n\t\t"
                    "ACK Number: %u\n\t\tData Offset (bytes): %u\n\t\t"
                    "%s\n\t\tWindow Size: %u\n\t\tChecksum: %s (0x%04x)\n",
                    src_port, dst_port, ntohl(tcpheader->sequence), 
                    ntohl(tcpheader->ack), offset_host, flagstr, 
                    ntohs(tcpheader->window_size), check, 
                    ntohs(tcpheader->checksum));
    free(src_port);
    free(dst_port);
    free(flagstr);
    free(pseudo);
}

char* get_flags(uint16_t offset_res_flags)
{
    char* flagstr = safe_malloc(sizeof(char) * 128);
    char* syn = (offset_res_flags & TCP_FLAG_MASK_SYN) ? "Yes" : "No";
    char* rst = (offset_res_flags & TCP_FLAG_MASK_RST) ? "Yes" : "No";
    char* fin = (offset_res_flags & TCP_FLAG_MASK_FIN) ? "Yes" : "No";
    char* ack = (offset_res_flags & TCP_FLAG_MASK_ACK) ? "Yes" : "No";
    snprintf(flagstr, sizeof(char) * 128, 
            "SYN Flag: %s\n\t\tRST Flag: %s\n\t\t"
            "FIN Flag: %s\n\t\tACK Flag: %s",
             syn, rst, fin, ack);
    return flagstr;
}

struct tcp_pseudo* get_tcp_pseudo(struct tcp* tcpheader, struct ip* ipheader)
{
    struct tcp_pseudo* pseudo = safe_malloc(sizeof(struct tcp_pseudo));
    memcpy(&(pseudo->header), tcpheader, sizeof(struct tcp));
    memcpy(&(pseudo->src), &(ipheader->src), sizeof(struct in_addr));
    memcpy(&(pseudo->dst), &(ipheader->dst), sizeof(struct in_addr));
    pseudo->zeros = 0;
    memcpy(&(pseudo->protocol), &(ipheader->protocol), sizeof(uint8_t));
    pseudo->tcp_len = get_tcp_len(tcpheader, ipheader);
    return pseudo;
}

uint16_t get_tcp_len(struct tcp* tcpheader, struct ip* ipheader)
{
    uint16_t ip_header_len = ((ipheader->ver_IHL) & IP_IHL_MASK) * WORD_LEN;
    uint16_t ip_field_length = ntohs(ipheader->length);
    uint16_t tcp_seg_len = ip_field_length - ip_header_len;
    return htons(tcp_seg_len);
}

void print_udphdr(struct udp* udpheader)
{
    char* src_port = determine_port(udpheader->src_port);
    char* dst_port = determine_port(udpheader->dst_port);
    fprintf(stdout, "\n\tUDP Header\n\t\tSource Port:  %s\n\t\t"
                    "Dest Port:  %s\n", src_port, dst_port);
    free(src_port);
    free(dst_port);
}

char* determine_port(uint16_t port_network)
{
    /* convert port from network to host order */
    uint16_t port_host = ntohs(port_network);
    char* port_num = safe_malloc(sizeof(char) * 7);
    if(port_host == PORT_DNS)
        strncpy(port_num, "DNS", 4);
    else if(port_host == PORT_HTTP)
        strncpy(port_num, "HTTP", 5);
    else if(port_host == PORT_TELNET)
        strncpy(port_num, "Telnet", 7);
    else if(port_host == PORT_FTP)
        strncpy(port_num, "FTP", 4);
    else if(port_host == PORT_POP3)
        strncpy(port_num, "POP3", 5);
    else if(port_host == PORT_SMTP)
        strncpy(port_num, "SMTP", 5);
    else
        port_num = safe_sprintf(port_num, port_host);
    return port_num;
}

char* safe_sprintf(char* str, uint16_t num)
{
    if(sprintf(str, "%u", num) < 0)
    {
        perror("sprintf failed! : ");
        exit(EXIT_FAILURE);
    }
    return str;
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