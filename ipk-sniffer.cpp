#include <pcap.h>
#include <iostream>
#include <getopt.h>
#include <string>
#include <bitset>
#include <sys/time.h>
#include <cstring>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
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

void got_packet(u_char* args, const struct pcap_pkthdr * header, const u_char *packet){
	char time_buff [80];
	struct tm *tim;
	tim=localtime(&(header->ts.tv_sec));
	strftime(time_buff, 80, "%Y-%m-%dT%X", tim);
	cout<<time_buff<<" ";


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

	struct ethernet_struct *ethernet; /* The ethernet header */

	const struct ip_struct *ip; /* The IP header */
	const struct tcp_struct *tcp; /* The TCP header */
	const char *payload; /* Packet payload */


	ethernet=(struct ethernet_struct*)packet;
	ip=(struct ip_struct*)(packet+SIZE_ETHERNET);
	u_int size_ip = ip->ip_vhl & 0x0F;
	tcp = (struct tcp_struct*)(packet + SIZE_ETHERNET+size_ip);
	u_int size_tcp=((tcp->th_offx2 & 0xf0) >> 4)*4;

	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	cout<<inet_ntoa(ip->ip_src)<<" : "<<tcp->th_sport;
	cout<<" > "<<inet_ntoa(ip->ip_dst)<<" : "<<tcp->th_dport<<", length "<<strlen(payload)<<" bytes"<<endl;
	cout<<payload<<endl;
		

	/*
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	ip_header = packet+SIZE_ETHERNET;
	ip_header_length=(*ip_header & 0x0F)*4;
	*/
	cout<<endl;
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
	cout<<exp<<endl;




	struct bpf_program t;

	struct bpf_program fp;

	if(pcap_compile(handle,&fp,"",0,PCAP_NETMASK_UNKNOWN)){
		cerr<<"Chyba kompilovania filtra"<<endl;
	}
	if(ret=pcap_setfilter(handle, &fp)){
		cerr<<"Chyba nastavovania filtra"<<endl;
	}
	struct pcap_pkthdr packet_header;

	cout<<"Reading..."<<endl;
	pcap_loop(handle, n,got_packet,NULL);
	return 0;
}



