#include "PacketSniffer.h"

#include <pcap.h>
#include <getopt.h>
#include <iostream>

void print_help(char* execName) {
	std::cout << std::endl << "PacketSniffer - тестовое задание для стажёра на позицию 'Разработчик C++/Python' (infotecs)" << std::endl << std::endl;
	std::cout << "Использование: " << execName << " [-h] [-f <filename> | -i [<interface>]] [-c <count>] [-o <filename>]" << std::endl;
	std::cout << "Опции: " << std::endl
		  << "\t-h (--help) - показать это сообщение." << std::endl
		  << "\t-f (--file) <filename> - считывать пакеты из файла." << std::endl
		  << "\t-i (--interface) [<interface>] - прослушивать интерфейс. Если не задано, будет выбран интерфейс по умолчанию." << std::endl
		  << "\t-c (--count) <count> - определяет количество пакетов, которые будут захвачены." << std::endl
		  << "\t-o (--output) <filename> - указать выходной файл для вывода статистики." << std::endl;
}

int main(int argc, char *argv[]) {
	static struct option long_options[] = {
		{"file", required_argument, nullptr, 'f'}, 	// Опция "считывание из файла"
		{"interface", optional_argument, nullptr, 'i'}, // Опция "слушать с интерфейса"
		{"count", required_argument, nullptr, 'c'},	// Количество пакетов
		{"out", required_argument, nullptr, 'o'},	// Выходной файл
		{"help", no_argument, nullptr, 'h'}		// Помощь
	};

	PacketSniffer* sniffer = nullptr;
	int packetCount = -1;
	std::string outFileName = "out.csv";
	std::string netInterfaceName;
	int opt;

	try {
		while ((opt = getopt_long(argc, argv, "c:f:o:hi::", long_options, nullptr)) != -1) {
			switch(opt) {
				case 'h':
					print_help(argv[0]);
					return 0;
				case 'f':
					std::cout << "Чтение пакетов из файла " << optarg << std::endl;
					sniffer = PacketSniffer::fromFile(std::string(optarg));
					break;
				case 'i':
					netInterfaceName = optarg ? std::string(optarg) : std::string();
					std::cout << "Захват пакетов с интерфейса " << (optarg ? optarg : "по умолчанию")
						  << std::endl;
					sniffer = PacketSniffer::fromInterface(netInterfaceName);	
					break;
				case 'c':
					packetCount = atoi(optarg);
					break;	
				case 'o':
					outFileName = std::string(optarg);
					break;
				case '?':
					print_help(argv[0]);
					return 1;
			}	
		}
					
		if (optind < argc) {
			std::cerr << "Ошибка: неизвестный аргумент '" << argv[optind] << "'\n";
			print_help(argv[0]);
			return 1;
		}

		// Используем интерфейс по умолчанию, если программа выполняется без опций
		if (!sniffer) {
			std::cout << "Используется интерфейс по умолчанию." << std::endl;
			sniffer = PacketSniffer::fromInterface();
			packetCount = 1000;
		}

		sniffer->startCapture(packetCount);
		sniffer->toCSV(outFileName);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
