#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <pcap.h>
#include <unordered_map>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Ключ для unordered_map, представляющий поток (комбинация IP адресов и портов)
struct FlowKey {
	uint32_t ip_src;
	uint32_t ip_dest;
	uint32_t port_src;
	uint32_t port_dest;

	bool operator==(const FlowKey& other) const {
		return ip_src == other.ip_src && ip_dest == other.ip_dest &&
		       port_src == other.port_src && port_dest == other.port_dest;
	}
};

// Хэш для FlowKey
struct FlowKeyHash {
	size_t operator()(const FlowKey& key) const {
		return std::hash<uint32_t>()(key.ip_src) ^
		       std::hash<uint32_t>()(key.ip_dest) ^
		       std::hash<uint32_t>()(key.port_src) ^
		       std::hash<uint32_t>()(key.port_src);
	}
};

// Структура для хранения статистики потока (количество пакетов и количество переданных байт)
struct FlowStats {
	int packet_count = 0;
	int byte_count = 0;
};

// Класс, отвечающий за обработку, анализ пакетов и вывод информации в CSV-файл
class PacketAnalyzer {
public:
	// Размер заголовка Ethernet - всегда 14 байт
	static const int SIZE_ETHERNET_HEADER = 14;

	// Основной метод - анализ пакета и обновление статистики по потоку
	void analyzePacket(const struct pcap_pkthdr* packetHeader, const u_char* packet);

	// Геттер мапы потоков
	std::unordered_map<FlowKey, FlowStats, FlowKeyHash> getFlowMap() const;
	int getUnrecognized() const;

private:
	std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flowMap; // Поток -> статистика
	int unrecognized = 0; // Количество пакетов, инкапсулирующих не TCP/UDP
};

#endif
