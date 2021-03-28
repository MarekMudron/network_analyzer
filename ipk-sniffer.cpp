#include <pcap.h>
#include <iostream>
#include <getopt.h>
#include <string>

using namespace std;

void print_help(){
	string help="-i rozhranie\tprave jedno rozhranie, na ktorom se bude pocuvat."
		"\t\tAk nebude tento parameter uvedeny, alebo bude uvedene len -i bez hodnoty,"
		"\t\tvypise sa zoznam aktivnych rozhrani"
		"-p cislo\tfiltrovenie paketov na danom rozhrani podla portu "
		"\t\tak nebude tento parameter uvedeny, uvazuju sa vsetkyy porty"
		"\t\tak je parameter uvedeny, moze se dany port vyskytnut ako v source,"
		"\t\ttak v destination casti"
		"-t | --tcp\tbude zobrazovat iba TCP pakety"
		"-u | --udp\tbude zobrazovat iba UDP pakety"
		"--icmp\tbude zobrazovat iba ICMPv4 a ICMPv6 pakety"
		"--arp\tbude zobrazovat iba ARP rámce"
		"-n pocet\turcuje pocet paketov, ktere sa maju zobrazit"
		"\t\tak nie je uvedene, uvazuje sa zobrazene len jedneho paketu";
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
				if(argv[i+1][0]=='-'){
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
				if(argv[i+1][0]=='-'){
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
				if(argv[i+1][0]=='-'){
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
int main(int argc, char** argv){
	//cout<<argc<<endl;
	parse_args(argc, argv);
	auto [tcp, udp, icmp, arp, interface, port, n] = parse_args(argc, argv);
	cout<<"tcp: "<<tcp<<endl;
	cout<<"udp: "<<udp<<endl;
	cout<<"icmp: "<<icmp<<endl;
	cout<<"arp: "<<arp<<endl;
	cout<<"interface: "<<interface<<endl;
	cout<<"port: "<<port<<endl;
	cout<<"n: "<<n<<endl;
	return 0;
}
