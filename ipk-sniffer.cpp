#include <pcap.h>
#include <iostream>
#include <getopt.h>
#include <string>
#include <bitset>
#include <iomanip>
#include <sys/time.h>
#include <cstring>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ARP 0x0806
using namespace std;

void print_help(){
	string help="-i rozhranie\tprave jedno rozhranie, na ktorom se bude pocuvat.\n"
		"\t\tAk nebude tento parameter uvedeny, alebo bude uvedene len -i bez hodnoty,\n"
		"\t\tvypise sa zoznam aktivnych rozhrani\n\n"
		"-p cislo\tfiltrovenie paketov na danom rozhrani podla portu\n"
		"\t\tak nebude tento parameter uvedeny, uvazuju sa vsetkyy porty\n"
		"\t\tak je parameter uvedeny, moze se dany port vyskytnut ako v source,\n"
		"\t\ttak v destination casti\n"
		"-t | --tcp\tbude zobrazovat iba TCP pakety\n\n"
		"-u | --udp\tbude zobrazovat iba UDP pakety\n\n"
		"--icmp\t\tbude zobrazovat iba ICMPv4 a ICMPv6 pakety\n\n"
		"--arp\t\tbude zobrazovat iba ARP rámce\n\n"
		"-n pocet\turcuje pocet paketov, ktere sa maju zobrazit\n\n"
		"\t\tak nie je uvedene, uvazuje sa zobrazene len jedneho paketu\n";
	cout<<help<<endl;
}

auto parse_args(int argc, char** argv){
	struct retVals {
		bool tcp, udp, icmp, arp;
		string interface, port;
		int n;
	};
	int n=1;
	bool tcp=false,
		 udp=false,
		 icmp=false,
		 arp=false;
	string interface, port;

	for(int i=1; i < argc; ++i){
		string arg=argv[i];
		bool ok=true;
		if((arg=="-i") || (arg=="--interface")){
			if(interface==""){
				if(i+1==argc || argv[i+1][0]=='-'){
					continue;
				}else{
					interface=argv[++i];
				}	
			}else{
				cerr<<"Viacnasobne pouzite parametra \'interface\'"<<endl;
				exit(1);
			}	
			
		}else if(arg=="--port" || arg== "-p"){
			if(port==""){
				if(i+1==argc || argv[i+1][0]=='-'){
					cerr<<"Chyba: nespravna hodnota parametra \'port\'"<<endl;	
					exit(1);
				}else{
					port=argv[++i];
				}	
			}else{
				cerr<<"Viacnasobne pouzite parametra \'port\'"<<endl;
				exit(1);
			}	
		}else if(arg== "-n"){
			if(n==1){
				if(i+1==argc || argv[i+1][0]=='-'){
					cerr<<"Chyba: nespravna hodnota parametra \'n\'"<<endl;	
					exit(1);
				}else{
					n=stoi(argv[++i]);
				}	
			}else{
				cerr<<"Viacnasobne pouzite parametra \'n\'"<<endl;
				exit(1);
			}	
		}else if(arg=="--help" || arg== "-h"){
			print_help();
			exit(0);
		}else if(arg=="--tcp" || arg=="-t"){
			tcp=true;
		}else if(arg=="--udp" || arg== "-u"){
			udp=true;
		}else if(arg=="--icmp"){
			icmp=true;
		}else if(arg=="--arp"){
			arp=true;
		}else{
			cerr<<"Neznamy parameter: "<<argv[i]<<endl;
			exit(1);
		}
	}
	return retVals {tcp, udp, icmp, arp ,interface, port, n};
}

void list_active_devs(){

		pcap_if_t* alldevsp;
		char  errbuf[PCAP_ERRBUF_SIZE];
		int x;
		x = pcap_findalldevs(&alldevsp, errbuf);
		while(alldevsp!=NULL){
			bitset<16> y(alldevsp->flags);
			//ak je zariadenie aktivne tak ho vypiseme
			if(y[1]){
				cout<<(alldevsp->name)<<endl;
			}
			alldevsp=alldevsp->next;
		}
}

void print_content(const u_char* packet, u_int len){
	int i=0,j = 0;
	while(i < len){
		cout<<"0x"<<setw(4)<<setfill('0')<<hex<<i<<":\t";
		j = 0;
		while(j < 16 && i < len) {
			cout<<setw(2)<<setfill('0')<<hex<<(int)packet[i]<<" ";
			j++;
			i++;
		}
		if(j!=16){
			for(int k = 0; k < (16 - j); ++k){
				cout<<"   ";
			}
		}
		cout<<dec;
		cout<<"\t";
		i-=j;
		j=0;
		while(j < 16 && i < len) {
			if(isprint(packet[i])){
				cout<<packet[i];
			}else{
				cout<<".";
			}
			j++;
			i++;
		}
		cout<<endl;
	}
}

struct ethernet_struct {
	u_char src [ETHER_ADDR_LEN];
	u_char dest [ETHER_ADDR_LEN];
	u_short ether_type;
};

struct ip_struct {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

struct tcp_struct {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int th_seq;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
};

struct arp_struct {
	unsigned short htype;
	unsigned short ptype;
	u_char hlen;
	u_char plen;
	unsigned short oper;
	u_char sha[6]; // sender hardware address
	u_char spa[4]; // sender protocol address
	u_char tha[6]; // target hardware address
	u_char tpa[4]; // target protocol address
};

void print_time(const struct pcap_pkthdr* header){
	char time_buff [80];
	struct tm *tim;
	tim=localtime(&(header->ts.tv_sec));
	strftime(time_buff, 80, "%Y-%m-%dT%X", tim);
	cout<<time_buff;
}

void handle_ipv4(const struct pcap_pkthdr* header, const u_char* packet){
	
}

void handle_ipv4(const struct pcap_pkthdr* header, const u_char* packet){

	const struct ip_struct* ip;
	const struct tcp_struct *tcp;
	const char* payload;
	u_int size_ip;
	u_int size_tcp;

	ip=(struct ip_struct*)(packet+SIZE_ETHERNET);
	//size_ip = ((ip->ip_vhl) & 0x0f)*4;
	if(size_ip < 20){
		cerr<<"\t\tInvalid IP header size..."<<endl;
		return;
	}

	switch(ip->ip_p){
		case IPPROTO_TCP:
			protocol= "TCP";
			handle_tcp(header, packet)
			break;
		case IPPROTO_UDP:
			handle_udp(header, packet)
			break;
		case IPPROTO_ICMP:
			protocol= "ICMP";
			handle_icmp(header, packet)
			break;
		/*
		case IPPROTO_IP:
			protocol= "IP";
			break;
			*/
		default:
			cout<<"Neznamy protokol"<<endl;
			return;
	}
	return;

	tcp=(struct tcp_struct*)(packet+SIZE_ETHERNET+size_ip);
	size_tcp=(((tcp->th_offx2) & 0xf0)>>4)*4;
	if(size_tcp < 20){
		cerr<<"\t\tInvalid TCP header size..."<<endl;
		return;
	}

	print_time(header);
	cout<<endl<<" "<<inet_ntoa(ip->ip_src)<<" : "<<endl;
	cout<<"To   "<<inet_ntoa(ip->ip_dst)<<endl;

	payload=(char*)(packet+SIZE_ETHERNET+size_ip + size_tcp);
	u_int payload_size = ntohs(ip->ip_len) - (size_ip+size_tcp);
	//cout<<endl<<payload_size;
	if(payload_size>0){
		cout<<"length "<<payload_size<<" bytes"<<endl;
		print_payload(payload, payload_size);
	}else{
		cout<<"INVALID SIZE"<<endl;

	}
	cout<<endl;
}

void handle_ipv6(const struct pcap_pkthdr* header, const u_char* packet){
	print_time(header);
}

void print_mac(const u_char* val){
	for(int i = 0; i < 5; ++i){
		cout<<setw(2)<<setfill('0')<<hex<<(int)val[i]<<":";
	}
	cout<<setw(2)<<setfill('0')<<hex<<(int)val[5];
}

void print_ip(const u_char* val){
	for(int i = 0; i < 3; ++i){
		cout<<dec<<((int)(val[i]))<<".";
	}
	cout<<dec<<((int)(val[3]));
}


void handle_arp(const struct pcap_pkthdr* header, const u_char* packet){
	struct arp_struct* arp = (struct arp_struct*)(packet+SIZE_ETHERNET);
	print_time(header);
	print_ip(arp->spa);
	cout<<endl<<"Sender MAC: ";
	print_mac(arp->sha);
	cout<<endl<<"Sender IP: ";
	print_ip(arp->spa);
	cout<<endl<<"Target MAC: ";
	print_mac(arp->tha);
	cout<<endl<<"Target IP: ";
	print_ip(arp->tpa);
	cout<<endl<<"length: "<<header->caplen<<" bytes";
	if(arp->htype==1){
		cout<<endl<<"Ethernet type: Ethernet";
	}
	cout<<endl<<"Protocol type: ";
	if(ntohs(arp->ptype)==0x0800){
		cout<<"IPv4"<<endl;
	}else if(ntohs(arp->ptype)==0x86dd){
		cout<<"IPv6"<<endl;
	}else{
		cout<<endl;
	}
	print_content(packet, header->caplen);
	cout<<endl;
	cout<<endl;	
}


void got_packet(u_char* args, const struct pcap_pkthdr * header, const u_char *packet){
	struct ethernet_struct* ethernet=(struct ethernet_struct*)packet;
	const u_char* frame_content = packet;
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IPV4){
		handle_ipv4(header, frame_content);
	}if(ntohs(ethernet->ether_type)==ETHERTYPE_IPV6){
		return;
		handle_ipv6(header, frame_content);
	}else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP){
		handle_arp(header, frame_content);
	}else{
		cout<<"Neznamy paket"<<endl;
	}
}









int main(int argc, char** argv){
	//cout<<argc<<endl;
	auto [tcp, udp, icmp, arp, interface, port, n] = parse_args(argc, argv);
	cout<<"tcp: "<<tcp<<endl;
	cout<<"udp: "<<udp<<endl;
	cout<<"icmp: "<<icmp<<endl;
	cout<<"arp: "<<arp<<endl;
	cout<<"interface: "<<interface<<endl;
	cout<<"port: "<<port<<endl;
	cout<<"n: "<<n<<endl;
	cout<<endl;

	//ak interface nespecifikovany -> vypis aktivnych rozhrani
	if(interface==""){
		list_active_devs();	
		return 0;
	}


	char  errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_create(interface.c_str(), errbuf);
	// ak chyba nastavovania promiskuitneho modu -> exit
	if(pcap_set_promisc(handle, 1)){
		cerr<<"Chyba nastavovania promiskuitneho modu"<<endl;
		exit(2);
	}
	// aktivacia pripojenia
	int ret = pcap_activate(handle);

	if(ret<0){
		cerr<<"Nastala CHYBA pri aktivovani pripojenia k zariadeniu \'"<<interface<<"\'"<<endl;
		cerr<<pcap_geterr(handle)<<endl;
		exit(2);
	}else if(ret > 0){
		cerr<<"Pripojenie k zariadeniu \'"<<interface<<"\' prebehlo uspesne s varovaniami"<<endl;
	}
	string exp="";
	// tcp / udp
	if(udp && !tcp){
		exp+="udp ";
	}else if(tcp && !udp){
		exp+="tcp ";
	}

	// icmp / arp
	if(icmp && !arp){
		exp+="icmp ";
	}else if(!icmp && arp){
		exp+="arp ";
	}

	// port
	if(port!=""){
		exp += "port "+port;
	}	




	struct bpf_program t;

	struct bpf_program fp;

	if(pcap_compile(handle,&fp,exp.c_str(),0,PCAP_NETMASK_UNKNOWN)){
		cerr<<"Chyba kompilovania filtra"<<endl;
	}
	if(ret=pcap_setfilter(handle, &fp)){
		cerr<<"Chyba nastavovania filtra"<<endl;
	}
	struct pcap_pkthdr packet_header;

	cout<<"Reading..."<<endl;
	pcap_set_timeout(handle, 100);
	pcap_loop(handle, n,got_packet,NULL);
	return 0;
}



