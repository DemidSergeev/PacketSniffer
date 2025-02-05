#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "PacketAnalyzer.h"

#include <pcap.h>
#include <iostream>
#include <string>

class PacketSniffer {
public:
	static const int MAX_CAPTURE_BYTES = 2048, PROMISC = 1, TIMEOUT_MS = 1000;

	// Фабричные методы для создания объекта по имени сетевого интерфейса/.pcap-файла
	static PacketSniffer fromInterface(const std::string& networkInterfaceName);
	static PacketSniffer fromFile(const std::string& pcapFileName);
	// Деструктор с освобождением ресурсов
	~PacketSniffer();
	// Метод для захвата указанного числа пакетов
	// (packetCount = -1 - захватывает бесконечно до возникновения ошибки)
	void startCapture(int packetCount = -1);
	// Метод для вывода информации в CSV-файл
	void toCSV(std::string& fileName) const;
private:
	pcap_t *handle = nullptr; // handle сессии захвата
	std::string filter_exp = "ip"; // фильтр-выражение
	bpf_program fp; // структура, в которую компилируется фильтр-выражение
	PacketAnalyzer packetAnalyzer; // объект для анализа пакетов

	// Конструктор с инициализацией handle и установкой фильтра на IPv4
	explicit PacketSniffer(pcap_t* pcapHandle, const std::string& errMsg);
	// Функция обработки для отдельного пакета
	static void packetHandler(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet);
};

#endif
