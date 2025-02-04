#include "PacketSniffer.h"

#include <pcap.h>
#include <iostream>
#include <string>

#define MAX_CAPTURE_BYTES 2048
#define PROMISC 1
#define TIMEOUT_MS 1000

PacketSniffer PacketSniffer::fromInterface(const std::string& netInterfaceName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(netInterfaceName.c_str(), MAX_CAPTURE_BYTES, PROMISC, TIMEOUT_MS, errbuf);
	return PacketSniffer(handle, errbuf);
}

PacketSniffer PacketSniffer::fromFile(const std::string& pcapFileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcapFileName.c_str(), errbuf);	
	return PacketSniffer(handle, errbuf);
}

PacketSniffer::PacketSniffer(pcap_t* pcapHandle, const std::string& errMsg) : handle(pcapHandle) {
	if (!pcapHandle) {
		throw std::runtime_error("Ошибка при открытии объекта: " + errMsg);
	}	
	std::cout << "pcapHandle создан: адрес " << pcapHandle << std::endl;
}

PacketSniffer::~PacketSniffer() {
	if (handle) {
		pcap_close(handle);
	}
}
		
