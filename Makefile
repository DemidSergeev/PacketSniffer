CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++17
OBJECTS = main.o PacketSniffer.o PacketAnalyzer.o

sniff_c: $(OBJECTS)
	$(CXX) -o sniff_c $(OBJECTS) -lpcap
main.o: PacketSniffer.h
PacketSniffer.o: PacketSniffer.h PacketAnalyzer.h
PacketAnalyzer.o: PacketAnalyzer.h
clean:
	rm -f sniff_c $(OBJECTS)
