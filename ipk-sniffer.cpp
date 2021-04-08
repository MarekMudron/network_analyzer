#include <pcap.h>
#include <iostream>
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
	//vypis pomocneho hlasenia pri parametri -h | --help
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
	//spracovanie argumentov z CLI
	
	//struktura ktoru vratime 
	struct retVals {
		bool tcp, udp, icmp, arp;
		string interface, port;
		int n;
	};
	// predvoleny pocet paketov je 1
	int n=1;

	//dalsie predvolene hodnoty
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
	//vypis pouzitelnych rozhrani
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
	//vypise obsah paketu v pozadovanej forme
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

struct ipv4_struct {
	u_char ip_vhl;		
	u_char ip_tos;	
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
};

struct ipv6_struct {
	u_int shit1;
	u_short shit2;
	u_char next_header;
	u_char shit3;
	u_char source_ip[16];
	u_char dest_ip[16];	
};


struct tcp_struct {
	u_short th_sport;
	u_short th_dport;
	u_int th_seq;	
	u_int th_ack;
	u_char th_offx2;
};

struct udp_struct {
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_checksum;
};

struct icmp_struct {
	u_int shit1;
	u_int shit2;
	u_int shit3;
	u_int source_ip;
	u_int destination_ip;
	u_int shit4;
};

struct arp_struct {
	unsigned short htype;
	unsigned short ptype;
	u_char hlen;
	u_char plen;
	unsigned short oper;
	u_char sha[6];
	u_char spa[4];
	u_char tha[6];
	u_char tpa[4];
};

void print_time(const struct pcap_pkthdr* header){
	// vypise cas vo formate RFC3339
	char buf [80];
	struct tm *p = localtime(&(header->ts.tv_sec));
    size_t len = strftime(buf, sizeof buf - 1, "%FT%T%z", p);
    if (len > 1) {
		char minute[] = { buf[len-2], buf[len-1], '\0'  };
	    sprintf(buf + len - 2, ":%s", minute);
	}
	cout<<buf;
}


void print_ipv6(const u_char* val){
	//vypise ipv6 adresu
	for(int i = 0; i < 14; ++i){
		cout<<setw(2)<<setfill('0')<<hex<<(int)val[i]<<setw(2)<<setfill('0')<<hex<<(int)val[i+1]<<":";
		i++;
	}
		cout<<setw(2)<<setfill('0')<<hex<<(int)val[14]<<setw(2)<<setfill('0')<<hex<<(int)val[15];
		cout<<dec;
}

void handle_ipv6(const struct pcap_pkthdr* header, const u_char* packet){
	// funkcia na spracovanie a vypis IPv6 paketu
	struct ipv6_struct* ip=(struct ipv6_struct*)(packet+SIZE_ETHERNET);
	u_char* nh=&(ip->next_header);	
	// spracovanie pomocnych hlaviciek IPv6
	u_int offset=34;


	//iterujeme cez extended headers v IPv6 pakete az kym sa nedostaneme na TCP alebo UDP alebo ICMP
	if(*nh==6 || *nh==17 || *nh == 58 || *nh==59){
		//tu sa nerobi nic
	}else{
		while(true){
			nh+=offset;
			if(*nh==0 || *nh==43|| *nh==60){
				//hop-by-hop, routing, a este cosi
				offset=8*(8+(u_char)(*(nh+8)));
			}else if(*nh==44){
				//fragment header
				offset=64;
			}else if(*nh==59){
				//oh, shit. koniec hlaviciek
				break;
			}else if(*nh==6 || *nh==17 || *nh == 58){
				break;
			}else{
				cerr<<"Neznamy header"<<endl;
				cout<<"IPv6"<<endl;
				print_time(header);
				cout<<" "; 
				print_ipv6(ip->source_ip);
				cout<<" > "; 
				print_ipv6(ip->dest_ip);
				cout<<endl;
				print_content(packet,header->caplen);
				cout<<endl<<endl;
				return;
			}
		}
	}

	//ak sme na no header tak vypiseme co mame a nezistujeme port a ani protokol
	if(*nh==59){
		cout<<"IPv6"<<endl;
		print_time(header);
		cout<<" "; 
		print_ipv6(ip->source_ip);
		cout<<" > "; 
		print_ipv6(ip->dest_ip);
		cout<<endl;
		print_content(packet,header->caplen);
		cout<<endl<<endl;
		return;
	}


	string protocol;
	//z destination optinos ideme zistit protokol
	u_short source_port, dest_port;
	
	switch(*nh){
		case 6:{
				protocol="TCP";
				const struct tcp_struct *tcp=(struct tcp_struct*)(nh+offset);
				source_port=ntohs(tcp->th_sport);
				dest_port=ntohs(tcp->th_dport);
				break;
			}
		case 17:{
				protocol="UDP";
				const struct udp_struct *udp=(struct udp_struct*)(nh+offset);
				source_port=ntohs(udp->udp_sport);
				dest_port=ntohs(udp->udp_dport);
			break;
			}
		case 58:
			protocol="ICMP";
			break;
		default:
			cout<<"Neznamy protokol"<<endl<<endl;
			return;
	}
	if(protocol=="UDP" || protocol=="TCP"){
		//vypise obsah a informacie o UDP alebo TCP pakete
		cout<<"IPv6 "<<protocol<<endl;
		print_time(header);
		cout<<" ";
		print_ipv6(ip->source_ip);
		cout<<":"<<source_port<<" > ";
		print_ipv6(ip->dest_ip);
		cout<<":"<<dest_port<<", ";
		cout<<"length "<<header->caplen<<" bytes"<<endl;
		print_content(packet, header->caplen);
		cout<<endl;
	}else{
		//vypise obsah ICMPv6 paketu
		cout<<"IPv6 "<<protocol<<endl;
		print_time(header);
		cout<<" ";
		print_ipv6(ip->source_ip);
		cout<<" > ";
		print_ipv6(ip->dest_ip);
		cout<<", ";
		cout<<"length "<<header->caplen<<" bytes"<<endl;
		print_content(packet, header->caplen);
		cout<<endl;

	}
}


void handle_ipv4(const struct pcap_pkthdr* header, const u_char* packet){
	// spracovanie a vypis ipv4 paketu
	const struct ipv4_struct* ip;
	u_int size_ip_header;

	ip=(struct ipv4_struct*)(packet+SIZE_ETHERNET);
	size_ip_header = ((ip->ip_vhl) & 0x0f)*4;

	if(size_ip_header < 20){
		cerr<<"\t\tInvalid IP header size..."<<endl;
		return;
	}

	string protocol;
	u_short source_port, dest_port;
	switch(ip->ip_p){
		case IPPROTO_TCP:{
				protocol="TCP";
				const struct tcp_struct *tcp=(struct tcp_struct*)(packet+SIZE_ETHERNET+size_ip_header);
				source_port=ntohs(tcp->th_sport);
				dest_port=ntohs(tcp->th_dport);
				break;
			}
		case IPPROTO_UDP:{
				protocol="UDP";
				const struct udp_struct *udp=(struct udp_struct*)(packet+SIZE_ETHERNET+size_ip_header);
				source_port=ntohs(udp->udp_sport);
				dest_port=ntohs(udp->udp_dport);
			break;
			}
		case IPPROTO_ICMP:
			protocol="ICMP";
			break;
		default:
			cout<<"Neznamy protokol"<<endl<<endl;
			return;
	}
	if(ip->ip_p==IPPROTO_TCP || ip->ip_p==IPPROTO_UDP){
		//vypis TCP alebo UDP paketu
		cout<<"IPv4 "<<protocol<<endl;
		print_time(header);
		cout<<" "<<inet_ntoa(ip->ip_src)<<":"<<source_port<<" > ";
		cout<<inet_ntoa(ip->ip_dst)<<":"<<dest_port<<", ";
		cout<<"length "<<header->caplen<<" bytes"<<endl;
		print_content(packet, header->caplen);
		cout<<endl;
	}else{
		//vypis ICMP paketu
		cout<<"IPv4 "<<protocol<<endl;
		print_time(header);
		cout<<" "<<inet_ntoa(ip->ip_src)<<" > ";
		cout<<inet_ntoa(ip->ip_dst)<<", ";
		cout<<"length "<<header->caplen<<" bytes"<<endl;
		print_content(packet, header->caplen);
		cout<<endl;

	}
}


void print_mac(const u_char* val){
	//funkcia na vypis mac adresy
	//pouziva sa pri ARP packetoch
	for(int i = 0; i < 5; ++i){
		cout<<setw(2)<<setfill('0')<<hex<<(int)val[i]<<":";
	}
	cout<<setw(2)<<setfill('0')<<hex<<(int)val[5];
}

void print_ipv4(const u_char* val){
	//vypise ipv4 adresu
	for(int i = 0; i < 3; ++i){
		cout<<dec<<((int)(val[i]))<<".";
	}
	cout<<dec<<((int)(val[3]));
}


void handle_arp(const struct pcap_pkthdr* header, const u_char* packet){
	struct arp_struct* arp = (struct arp_struct*)(packet+SIZE_ETHERNET);
	if(ntohs(arp->ptype)==ETHERTYPE_IPV4){
		cout<<"ARP"<<endl;
		print_time(header);
		cout<<endl<<"Sender MAC: ";
		print_mac(arp->sha);
		cout<<endl<<"Sender IP: ";
		print_ipv4(arp->spa);
		cout<<endl<<"Target MAC: ";
		print_mac(arp->tha);
		cout<<endl<<"Target IP: ";
		print_ipv4(arp->tpa);
		cout<<endl<<"length: "<<header->caplen<<" bytes";
		cout<<endl;
		print_content(packet, header->caplen);
		cout<<endl;
	}else{
		//ak tam je nieco ine tak je to zle
		cout<<"Neznamy typ IP protokolu pri ARP"<<endl;
		return;
	}
}


void got_packet(u_char* args, const struct pcap_pkthdr * header, const u_char *packet){
	//funkcia volana z pcap_loop vzdy ked dostane paket
	struct ethernet_struct* ethernet=(struct ethernet_struct*)packet;
	const u_char* frame_content = packet;
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IPV4){
		handle_ipv4(header, frame_content);
	}else if(ntohs(ethernet->ether_type)==ETHERTYPE_IPV6){
		handle_ipv6(header, frame_content);
	}else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP){
		handle_arp(header, frame_content);
	}else{
		cout<<"Neznamy paket"<<endl;
	}
}

int main(int argc, char** argv){
	//zistime hodnotu premennych pomocou ktorych skladame filter
	auto [tcp, udp, icmp, arp, interface, port, n] = parse_args(argc, argv);

	//ak interface nespecifikovany -> vypis aktivnych rozhrani
	if(interface==""){
		list_active_devs();	
		return 0;
	}

	char  errbuf[PCAP_ERRBUF_SIZE];
	//vytvorime spojenie s pozadovanym rozhranim
	pcap_t* handle = pcap_create(interface.c_str(), errbuf);
	// ak chyba nastavovania promiskuitneho modu -> exit
	if(pcap_set_promisc(handle, 1)){
		cerr<<"Chyba nastavovania promiskuitneho modu"<<endl;
		exit(2);
	}
	// aktivacia pripojenia
	pcap_set_immediate_mode(handle, 1);
	int ret = pcap_activate(handle);

	if(ret<0){
		cerr<<"Nastala CHYBA pri aktivovani pripojenia k zariadeniu \'"<<interface<<"\'"<<endl;
		cerr<<pcap_geterr(handle)<<endl;
		exit(2);
	}else if(ret > 0){
		cerr<<"Pripojenie k zariadeniu \'"<<interface<<"\' prebehlo uspesne s varovaniami"<<endl;
		exit(2);
	}


	//exp predstavuje filter ktory pomocou setfilter nastavime pre pcap
	//v nasledujucich  podmienkach skladame tento filter z argumentov CLI
	string exp="";
	
	bool s = false;
	if(tcp){
		exp+="tcp";
		s=true;
	}
	if(udp){
		if(s){
			exp+=" or udp";
		}else{
			exp+="udp";
			s=true;
		}
	}
	if(icmp){
		if(s){
			exp+=" or icmp or icmp6";
		}else{
			exp+="icmp or icmp6";
			s=true;
		}
	}
	if(arp){
		if(s){
			exp+=" or arp";
		}else{
			exp+="arp";
			s=true;
		}
	}

	if(s){
		exp="("+exp+")";
		if(port != ""){
			exp+=" and port "+port;
		}
	}else{
		if(port != ""){
			exp+="port "+port;
		}
	}

	struct bpf_program fp;

	//skompilujeme pozadovany filter
	if(pcap_compile(handle,&fp,exp.c_str(),0,PCAP_NETMASK_UNKNOWN)){
		cerr<<"Chyba kompilovania filtra"<<endl;
		exit(2);
	}

	//aplikujeme pozadovany filter
	if(ret=pcap_setfilter(handle, &fp)){
		cerr<<"Chyba nastavovania filtra"<<endl;
		exit(2);
	}
	//cyklus ktora nacita n paketov
	pcap_loop(handle, n,got_packet,NULL);
	return 0;
}



