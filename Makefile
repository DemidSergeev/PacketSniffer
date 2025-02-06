CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++17
OBJECTS = main.o PacketSniffer.o PacketAnalyzer.o

sniff.out: $(OBJECTS)
	$(CXX) -o sniff.out $(OBJECTS) -lpcap
main.o: PacketSniffer.h
PacketSniffer.o: PacketSniffer.h PacketAnalyzer.h
PacketAnalyzer.o: PacketAnalyzer.h
clean:
	rm -f sniff.out $(OBJECTS)
