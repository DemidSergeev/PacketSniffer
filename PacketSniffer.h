#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <iostream>
#include <string>

class PacketSniffer {
public:
	static PacketSniffer fromInterface(const std::string& networkInterfaceName);
	static PacketSniffer fromFile(const std::string& pcapFileName);
	~PacketSniffer();
	//void startCapture(int packetCount, int maxPacketSize);
private:
	pcap_t *handle = nullptr;

	explicit PacketSniffer(pcap_t* pcapHandle, const std::string& errMsg);
	//static void processPacket(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packetData);
};

#endif
