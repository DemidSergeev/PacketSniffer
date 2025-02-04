#include "PacketSniffer.h"

#include <pcap.h>
#include <cctype>
#include <iostream>

void processPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    int i = 0, *counter = (int *) arg;

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for (i=0; i<pkthdr->len; i++) {
        if (isprint(packet[i]))
	    printf("%c ", packet[i]);
	else
	    printf(". ");

	if ((i % 16 == 0 && i != 0) || i == pkthdr->len-1)
	    printf("\n");
    }

    return;
}

int main() {
	PacketSniffer sniff1 = PacketSniffer::fromFile("smallFlows.pcap");
	return 0;
}
