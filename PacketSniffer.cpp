#include "PacketSniffer.h"
#include "PacketAnalyzer.h"

#include <pcap.h>
#include <iostream>
#include <sstream>
#include <fstream>
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

// Вывод накопленной через PacketAnalyzer статистики в CSV-файл
void PacketSniffer::toCSV(const std::string& fileName) const {

	// Лямбда-функция для перевода IP из десятичного числа в вид xxx.xxx.xxx.xxx
	auto ipToStr = [](uint32_t ip) {
		std::ostringstream oss;
	    	oss << ((ip >> 24) & 0xFF) << "." 
		    << ((ip >> 16) & 0xFF) << "." 
		    << ((ip >> 8) & 0xFF) << "." 
		    << (ip & 0xFF);
	    return oss.str();
	};

	std::fstream out(fileName.c_str(), std::ios::out);
	if (!out) {
	    std::cerr << "Ошибка: не удалось открыть файл " << fileName << " для записи." << std::endl;
	    return;
	}
	auto flowMap = packetAnalyzer.getFlowMap();
	std::cout << "Размер flowMap: " << flowMap.size() << std::endl;
	out << "IP source,IP dest,Port source,Port dest,Total packets,Total bytes" << std::endl;
	for (const auto& [flowKey, flowStats] : flowMap) {
		out << ipToStr(flowKey.ip_src) << "," << ipToStr(flowKey.ip_dest) << "," << flowKey.port_src
		    << "," << flowKey.port_dest << "," << flowStats.packet_count << ","
		    << flowStats.byte_count << std::endl;
	}
	out.close();
	std::cout << "Информация сохранена в " << fileName << std::endl;
}
