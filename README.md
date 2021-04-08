Sniffer paketov
===============
Softvér umožňujúci spracovanie a zobrazenie prevádzky dát z internetu. Táto funkcionalita je umožnená pre koncové zariadenia ako aj pre zariadenia, ktorými pakety prechádzajú.
Na používane sú potrebné administrátorské práva.

Vlastnosti
------------
* filtrovanie paketov na základe argumentov z príkazového riadku
* podpora IPv4 a IPv6
* podpora protokolov UDP a TCP  transportnej vrstvy
* podpora IP, ICMP a ARP sieťovej vrstvy
* výpis celého obsahu paketu 
* zistenie niektorých informácií z hlavičiek jednotlivých vrstiev (zdrojová IP, cieľová IP, zdrojový port, cieľový port, čas príchodu paketu...)

Obmedzenia
----------
* podpora len Ethernetu na linkovej vrstve

Dependencie
---------
* balík libpcap
* C++ štandard 17

V Linuxe možná inštaláciou pomocou príkazu `sudo apt-get install libpcap-dev`

Inštalácia
-----------
Príkazom `make` pomocou priloženého Makefile.

Implementačné detaily
-------------------
Na spracovanie argumentov z príkazového riadku nebola použitá povinná knižnica `getopt.h`.

Príklady použitia
--------------
* `./ipk-sniffer -i` vypíše možné rozhrania, z ktorých je možné prijímať pakety
* `./ipk-sniffer -i lo --tcp` prijme len TCP pakety z adresy 127.0.0.1 (localhost) 
* `./ipk-sniffer -i lo -t` takisto ako príklad vyššie
* `./ipk-sniffer -h` zobrazí pomocné hlásenie s informáciami o použití argumentov
* `./ipk-sniffer -i eth0 -p 433 --udp` prijme UDP pakety na rozhraní eth0 na porte 433

Odovzdávané súbory
-----------------
* `README.md`
* `Makefile`
* `manual.pdf`
* `ipk-sniffer.cpp`

Použité materiály
-----------------
[Manuál balíka PCAP](https://www.tcpdump.org/manpages/pcap.3pcap.html)

[Tutoriál balíka PCAP](https://www.tcpdump.org/pcap.html)

https://www.devdungeon.com/content/using-libpcap-c

