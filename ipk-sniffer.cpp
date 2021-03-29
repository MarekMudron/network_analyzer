#include <pcap.h>
#include <iostream>
#include <getopt.h>
#include <string>
#include <bitset>

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
	int n=0;
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
			if(n==0){
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
	cout<<packet<<endl;
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
	/*string exp="";
	if(udp && !tcp){
		exp+="udp ";
	}else if(tcp && !udp){
		exp+="tcp ";
	}else if(tcp && udp){
		exp+="(tcp and udp) ";
	}
	if(port!=""){
		exp+="port " + port;
	}
	cout<<exp<<endl;
	*/
	//struct bpf_program fp;


	//ret=pcap_compile(handle,&fp,"",0,PCAP_NETMASK_UNKNOWN);
	pcap_loop(handle, 10,got_packet,NULL);
	return 0;
}
