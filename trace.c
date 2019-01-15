#include "trace.h"

int main(int argc, char* argv[]) 
{
    unsigned char frame_buf[PCAP_ERRBUF_SIZE];
    pcap_t* tracefile = NULL;
    struct pcap_pkthdr* pktheader = NULL;
    const u_char* pktdata = NULL;
    int pktnum = 0;
    uint32_t pktlen = 0;

    tracefile = pcap_open_offline(argv[1], (char*)frame_buf);
    if(tracefile == NULL) 
    {
        fprintf(stderr, "%s\n", frame_buf);
        exit(EXIT_FAILURE);
    }
    while(pcap_next_ex(tracefile, &pktheader, &pktdata) != -2)
    {
        pktnum++;
        pktlen = (uint32_t)(pktheader->len);
        fprintf(stdout, "\nPacket number: %d  Packet Len: %u\n\n", pktnum, pktlen);
    }

    pcap_close(tracefile);
    exit(EXIT_SUCCESS);
}