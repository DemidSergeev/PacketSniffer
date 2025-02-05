#include "PacketSniffer.h"

#include <pcap.h>
#include <iostream>

int main() {
	std::string fileName = "smallFlows.pcap", netInterfaceName = "enp9s0";
	PacketSniffer sniff1 = PacketSniffer::fromFile(fileName);
	PacketSniffer sniff2 = PacketSniffer::fromInterface(netInterfaceName);
	return 0;
}
