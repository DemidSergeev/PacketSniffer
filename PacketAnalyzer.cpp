#include "PacketAnalyzer.h"

#include <arpa/inet.h>

/* В текущей версии нет проверки на то, что packetHeader->caplen (длина захваченной части пакета) достаточна,
   чтобы пакет вмещал хотя бы заголовки Ethernet и IP/TCP минимальной длины. Из-за этого есть риск считывать
   данные за пределами пакета.
*/
void PacketAnalyzer::analyzePacket(const struct pcap_pkthdr* packetHeader, const u_char* packet) {
	// Отступаем 14 байт от начала пакета, чтобы пропустить заголовок Ethernet
	const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + SIZE_ETHERNET_HEADER);

	// Проверка на версию протокола IP
	if (ipHeader->ip_v != 4) return;

	int size_ip = ipHeader->ip_hl * 4;
	if (size_ip < 20) {
		std::cerr << "\tДлина заголовка IP меньше 20 байт: " << size_ip << std::endl;
		return;
	}

	// Получим IP-адреса из IP заголовка
	uint32_t ip_src = ntohl(ipHeader->ip_src.s_addr);
	uint32_t ip_dest = ntohl(ipHeader->ip_dst.s_addr);
	uint16_t port_src = 0, port_dest = 0;
	
	// Определим протокол в заголовке IP
	const struct tcphdr* tcpHeader = nullptr;
	const struct udphdr* udpHeader = nullptr;
	switch (ipHeader->ip_p) {
		// Протокол TCP
		case IPPROTO_TCP:
			tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + SIZE_ETHERNET_HEADER + size_ip);
			port_src = tcpHeader->th_sport;
			port_dest = tcpHeader->th_dport;
			break;
		// Протокол UDP
		case IPPROTO_UDP:
			udpHeader = reinterpret_cast<const struct udphdr*>(packet + SIZE_ETHERNET_HEADER + size_ip);
			port_src = udpHeader->uh_sport;
			port_dest = udpHeader->uh_dport;
			break;
		// Иной протокол
		default:
			std::cerr << "Протокол транспортного уровня не распознан. Анализатор работает только с TCP/UDP" << std::endl;
			return;
	}

	// Обновляем статистику по потоку
	FlowKey flowKey = {ip_src, ip_dest, port_src, port_dest};
	flowMap[flowKey].packet_count++;
	flowMap[flowKey].byte_count += packetHeader->len;
}
