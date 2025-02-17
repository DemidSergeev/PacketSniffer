#include "PacketSniffer.h"
#include "PacketAnalyzer.h"

#include <pcap.h>
#include <sys/stat.h> // Для chmod
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


// Фабричный метод для создания объекта PacketSniffer по имени сетевого интерфейса
PacketSniffer* PacketSniffer::fromInterface(std::string netInterfaceName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if (netInterfaceName.empty()) {
		pcap_if_t *alldevs;
		int result = pcap_findalldevs(&alldevs, errbuf);
		if (result == PCAP_ERROR) {
			throw std::runtime_error("Ошибка при поиске интерфейсов: " + std::string(errbuf));
		} else if (result != 0) {
			throw std::runtime_error("Доступные интерфейсы не найдены. Стоит попробовать запустить с sudo.");
		} else {
			netInterfaceName = alldevs->name;
		}
	}
	std::cout << "Имя интерфейса: " << netInterfaceName << std::endl;
	pcap_t* handle = pcap_open_live(netInterfaceName.c_str(), MAX_CAPTURE_BYTES, PROMISC, TIMEOUT_MS, errbuf);
	bool isFromFile = false;
	return new PacketSniffer(handle, isFromFile, errbuf);
}

// Фабричный метод для создания объекта PacketSniffer по имени .pcap-файла
PacketSniffer* PacketSniffer::fromFile(const std::string& pcapFileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcapFileName.c_str(), errbuf);	
	bool isFromFile = true;
	return new PacketSniffer(handle, isFromFile, errbuf);
}

// Конструктор, инициализирующий handle и устанавливающий фильтр на IPv4
PacketSniffer::PacketSniffer(pcap_t* pcapHandle, const bool _isFromFile, const std::string& errMsg)
			: handle(pcapHandle), isFromFileFlag(_isFromFile) {
	if (!pcapHandle) {
		throw std::runtime_error("Ошибка при открытии объекта:\n'" + errMsg + "'");
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
	std::cout << "Начат захват пакетов." << std::endl << "Захвачено пакетов:" << std::endl;
	packetAnalyzer.setPacketCount(packetCount);
	if (pcap_loop(handle, packetCount, packetHandler, reinterpret_cast<u_char*>(&packetAnalyzer)) == -1) {
		throw std::runtime_error("Ошибка при захвате пакетов: " + std::string(pcap_geterr(handle)));
	}
	packetAnalyzer.showCounts();
	std::cout << std::endl << "Захват пакетов завершён." << std::endl
		  << "Захвачено требуемых пакетов: " << packetAnalyzer.getCapturedCount() << std::endl
		  << "Пакетов с протоколом верхнего уровня, отличным от TCP и UDP: " << packetAnalyzer.getUnrecognizedCount() << std::endl;
}	

// Callback-обработчик для пакета
void PacketSniffer::packetHandler(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet) {
	auto* packetAnalyzer = reinterpret_cast<PacketAnalyzer*>(user);
	packetAnalyzer->analyzePacket(packetHeader, packet);
	int capturedCount = packetAnalyzer->getCapturedCount();
	int packetCount = packetAnalyzer->getPacketCount();
	packetCount = packetCount > 0 ? packetCount : 1000;
	if (capturedCount == 1 || capturedCount % (packetCount / 500) == 0) {
		packetAnalyzer->showCounts();
	}
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

	std::ofstream out(fileName.c_str(), std::ios::out);
	if (!out) {
		throw std::runtime_error("Ошибка: не удалось открыть файл " + fileName + " для записи. Проверьте разрешения.");
	}

	auto flowMap = packetAnalyzer.getFlowMap();
	std::cout << "Идентифицировано " << flowMap.size() << " потоков. " << std::endl;
	out << "IP source,IP dest,Port source,Port dest,Total packets,Total bytes" << std::endl;
	for (const auto& [flowKey, flowStats] : flowMap) {
		out << ipToStr(flowKey.ip_src) << "," << ipToStr(flowKey.ip_dest) << "," << flowKey.port_src
		    << "," << flowKey.port_dest << "," << flowStats.packet_count << ","
		    << flowStats.byte_count << std::endl;
	}
	out.close();
	std::cout << "Информация сохранена в " << fileName << std::endl;
}

bool PacketSniffer::isFromFile() const {
	return isFromFileFlag;
}
