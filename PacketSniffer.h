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
	static PacketSniffer* fromInterface(std::string netInterfaceName = "");
	static PacketSniffer* fromFile(const std::string& pcapFileName);
	// Деструктор с освобождением ресурсов
	~PacketSniffer();
	// Метод для захвата указанного числа пакетов
	// (packetCount = -1 - захватывает бесконечно до возникновения ошибки)
	void startCapture(const int packetCount = -1);
	// Метод для вывода информации в CSV-файл
	void toCSV(const std::string& fileName) const;

	// Геттер для isFromFile
	bool isFromFile() const;

private:
	pcap_t *handle = nullptr; // handle сессии захвата
	std::string filter_exp = "ip"; // фильтр-выражение
	bpf_program fp; // структура, в которую компилируется фильтр-выражение
	PacketAnalyzer packetAnalyzer; // объект для анализа пакетов
	const bool isFromFileFlag; // флаг для обозначения природы объекта - читает из файла или слушает интерфейс

	// Конструктор с инициализацией handle и установкой фильтра на IPv4
	explicit PacketSniffer(pcap_t* pcapHandle, const bool isFromFile, const std::string& errMsg);
	// Функция обработки для отдельного пакета
	static void packetHandler(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet);
};

#endif
