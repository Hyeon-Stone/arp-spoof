#include <stdint.h>
#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"
enum: int {
    REQ = 0,
    RPlY,
    INFECT,
    RECOVER
};
#pragma pack (push,1)
typedef struct{
    EthHdr eth_;
    ArpHdr arp_;
}EthArpPacket;

typedef struct ARP_Table{
    uint32_t SENDER_IP;
    uint8_t SENDER_MAC[6];
    uint32_t TARGET_IP;
    uint8_t TARGET_MAC[6];
}ARP_Table;
#pragma pack(pop)

void PrintMAC(char* msg, uint8_t *mac);

void PrintIP(char* msg, uint32_t ip);

void PrintAttcker(uint8_t *ATTACKER_MAC,  uint32_t ATTACKER_IP);

void Print(ARP_Table Table);

uint32_t Str2A(char *ip_string);

uint32_t ResolveAttackerIp(char *dev);

void  ResolveAttackerMac(char* dev, uint8_t *mac);

EthArpPacket MakeArp(int make_type ,uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac);

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac);

void Send(int make_type, pcap_t* handle, uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac);

void RelayPacket(pcap_t* handle, const u_char* data, struct pcap_pkthdr* header, uint8_t* attacker_mac, uint32_t sender_ip, uint8_t* sender_mac, uint32_t target_ip, uint8_t* target_mac);

void Relay(pcap_t* handle, uint8_t* ATTACKER_MAC, ARP_Table* Table, int pair_num);


