all:ipk-sniffer.cpp
	g++ -std=c++17 -o ipk-sniffer ipk-sniffer.cpp -lpcap
