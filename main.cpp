#include <cstdio>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <string.h>

#include "libnet.h"
#include "ethhdr.h"
#include "arphdr.h"


#define MAC_SIZE 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


EthArpPacket build_arp(int flag, char* src_ip, char* src_mac, char* dst_ip, char* dst_mac);
void send_packet(pcap_t* handle, EthArpPacket packet);
void send_arp(pcap_t* handle, char* my_mac, char* target_ip, char* sender_ip, char* sender_mac);
void my_macip(char* interface, char* my_ip, char* my_mac);
void find_sender_mac(pcap_t* handle, char* my_ip, char* my_mac, char* sender_ip, char* sender_mac);

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2>]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if ((argc%2 != 0) || argc < 4) {
		usage();
		return -1;
	}

	char my_ip[20];
	char my_mac[20];
	char* sender_ip;
	char sender_mac[20];
	char* target_ip; 
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i=2;i<argc;i+=2)
	{
		sender_ip = argv[i];    //access to pointer 
		target_ip = argv[i+1];

		my_macip(dev, my_ip, my_mac);
		find_sender_mac(handle, my_ip, my_mac, sender_ip, sender_mac);
		send_arp(handle, my_mac, target_ip, sender_ip, sender_mac);
	}	
	pcap_close(handle);
	
}


EthArpPacket build_arp(int flag, char* src_ip, char* src_mac, char* dst_ip, char* dst_mac)
{
	EthArpPacket packet;

	
	packet.eth_.dmac_ = Mac(dst_mac);
	packet.eth_.smac_ = Mac(src_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
                           
	if (flag == 1)                 //request or reply, check by flag                                   
		packet.arp_.op_ = htons(ArpHdr::Request);
 
	else if(flag == 2)
		packet.arp_.op_ = htons(ArpHdr::Reply);

	else
	{
		printf("flag error\n");
		exit(1);
	}

	packet.arp_.smac_ = Mac(src_mac);
	packet.arp_.sip_ = htonl(Ip(src_ip));
									
	if(memcmp("ff:ff:ff:ff:ff:ff", dst_mac, sizeof(dst_mac)))
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	else					
		packet.arp_.tmac_ = Mac(dst_mac);

	packet.arp_.tip_ = htonl(Ip(dst_ip));

	return packet;
}

void send_packet(pcap_t* handle, EthArpPacket packet)
{	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}

// EthArpPacket build_arp(int flag, char* src_ip, char* src_mac, char* dst_ip, char* dst_mac);
void send_arp(pcap_t* handle, char* my_mac, char* target_ip, char* sender_ip, char* sender_mac)
{
	EthArpPacket packet = build_arp(2, target_ip, my_mac, sender_ip, sender_mac);
	send_packet(handle, packet);
	printf("target ip : %s\n", target_ip);  // for check
	printf("sender ip : %s\n", sender_ip);
	printf("sender_mac : %s\n", sender_mac);
}

void my_macip(char* interface, char* my_ip, char* my_mac)
{

	uint8_t my_mac_func[MAC_SIZE];
	int sockfd;
	struct ifreq ifr;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("socket load failed\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, interface);



	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0 )
	{
		printf("mac load failed\n");
		close(sockfd);
		exit(1);
	}

	memcpy(my_mac_func, ifr.ifr_addr.sa_data, 6);
	sprintf(my_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			my_mac_func[0], my_mac_func[1]
		      , my_mac_func[2], my_mac_func[3]
		      , my_mac_func[4], my_mac_func[5]);

	ioctl(sockfd, SIOCGIFADDR, &ifr);


	//inet_ntop(AF_INET, (struct sockaddr_in*) ifr.ifr_addr.sa_data, my_ip, sizeof(struct sockaddr));


	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	strcpy(my_ip, inet_ntoa(sin -> sin_addr));


	close(sockfd);

	printf("MY IP: %s\n", my_ip);
	printf("MY MAC: %s\n", my_mac);
	
}
//EthArpPacket build_arp(int flag, char* src_ip, char* src_mac, char* dst_ip, char* dst_mac);

void find_sender_mac(pcap_t* handle, char* my_ip, char* my_mac, char* sender_ip, char* sender_mac)
{
	EthArpPacket packet;
	struct libnet_ethernet_hdr* ether;
	packet = build_arp(1, my_ip, my_mac, sender_ip, "ff:ff:ff:ff:ff:ff");
	send_packet(handle, packet);

	while(true)
	{
		char recv_src_ip[20];
		struct pcap_pkthdr* header;
		const u_char* packet_data;
		int res = pcap_next_ex(handle, &header, &packet_data);
		if (res == 0) 
		{
			printf("no packet has been captured\n");
			continue;
		}
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		ether = (struct libnet_ethernet_hdr *)packet_data;

		if(ntohs(ether->ether_type) == ETHERTYPE_ARP)
		{
			struct ether_arp* arp = (struct ether_arp*)(packet_data + 14);
			sprintf(recv_src_ip,"%d.%d.%d.%d", arp->arp_spa[0], arp->arp_spa[1]
							 , arp->arp_spa[2], arp->arp_spa[3]);
			if(strcmp(recv_src_ip, sender_ip) == 0)
				break;
			else 
				send_packet(handle, packet);
		
		}


	}
	
	u_int8_t* input_mac = (u_int8_t*)ether->ether_shost;
	sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x", input_mac[0], input_mac[1]
			              		           , input_mac[2], input_mac[3]
							   , input_mac[4], input_mac[5]);
 
}
