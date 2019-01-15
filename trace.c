#include "trace.h"

int main(int argc, char* argv[]) {
    unsigned char frame_buf[PCAP_ERRBUF_SIZE];
    pcap_t* tracefile = pcap_open_offline(argv[1], (char*)frame_buf);
    if(tracefile == NULL) {
        fprintf(stderr, "%s\n", frame_buf);
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}