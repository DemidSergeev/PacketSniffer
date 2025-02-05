#include "PacketSniffer.h"
#include "PacketAnalyzer.h"

#include <pcap.h>
#include <iostream>
#include <string>


// Фабричный метод для создания объекта PacketSniffer по имени сетевого интерфейса
PacketSniffer PacketSniffer::fromInterface(const std::string& netInterfaceName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(netInterfaceName.c_str(), MAX_CAPTURE_BYTES, PROMISC, TIMEOUT_MS, errbuf);
	return PacketSniffer(handle, errbuf);
}

// Фабричный метод для создания объекта PacketSniffer по имени .pcap-файла
PacketSniffer PacketSniffer::fromFile(const std::string& pcapFileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcapFileName.c_str(), errbuf);	
	return PacketSniffer(handle, errbuf);
}

// Конструктор, инициализирующий handle и устанавливающий фильтр на IPv4
PacketSniffer::PacketSniffer(pcap_t* pcapHandle, const std::string& errMsg) : handle(pcapHandle) {
	if (!pcapHandle) {
		throw std::runtime_error("Ошибка при открытии объекта: " + errMsg);
	}	
	// Компиляция фильтра из выражения filter_exp (у нас только IPv4 - поэтому он равен "ip")
	int optimize = 1;
	if (pcap_compile(handle, &fp, filter_exp.c_str(), optimize, PCAP_NETMASK_UNKNOWN) == -1) {
		throw std::runtime_error("Ошибка при компиляции фильтра " + std::string(filter_exp) + ": " + pcap_geterr(handle));
	}
	// Установка фильтра на handle
	if (pcap_setfilter(handle, &fp) == -1) {
		throw std::runtime_error("Ошибка при установке фильтра " + std::string(filter_exp) + ": " + pcap_geterr(handle));
	}
}

// Деструктор - закрытие handle
PacketSniffer::~PacketSniffer() {
	if (handle) {
		pcap_close(handle);
	}
}

// Метод для захвата указанного числа пакетов 
void PacketSniffer::startCapture(int packetCount) {
	// pcap_loop принимает u_char* в качестве последнего аргумента, поэтому кастим &packetAnalyzer к этому типу
	if (pcap_loop(handle, packetCount, packetHandler, reinterpret_cast<u_char*>(&packetAnalyzer)) == -1) {
		throw std::runtime_error("Ошибка при захвате пакетов: " + std::string(pcap_geterr(handle)));
	}
}	

// Callback-обработчик для пакета
void PacketSniffer::packetHandler(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet) {
	auto* packetAnalyzer = reinterpret_cast<PacketAnalyzer*>(user);
	packetAnalyzer->analyzePacket(packetHeader, packet);
}
