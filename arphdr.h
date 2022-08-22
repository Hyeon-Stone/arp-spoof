#include <stdint.h>
#pragma pack(push, 1)
typedef struct{
    uint16_t Hw_type;
    uint16_t Proto_type;
    uint8_t Hw_addr_len;
    uint8_t Proto_addr_len;
    uint16_t Opcode;
    uint8_t Src_mac[6];
    uint32_t Src_ip;
    uint8_t Tag_mac[6];
    uint32_t Tag_ip;
}ArpHdr;
#pragma pack(pop)

enum: uint16_t {
    REQUEST = 1, // req to resolve address
    REPLY = 2, // resp to previous request
    REVREQUEST = 3, // req protocol address given hardware
    REVREPLY = 4, // resp giving protocol address
    INVREQUEST = 8, // req to identify peer
    INVREPLY = 9 // resp identifying peer
}; // By gilgil

enum: uint16_t {
    NETROM = 0, // from KA9Q: NET/ROM pseudo
    ETHER = 1, // Ethernet 10Mbps
    EETHER = 2, // Experimental Ethernet
    AX25 = 3, // AX.25 Level 2
    PRONET = 4, // PROnet token ring
    CHAOS = 5, // Chaosnet
    IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
    ARCNET = 7, // ARCnet
    APPLETLK = 8, // APPLEtalk
    LANSTAR = 9, // Lanstar
    DLCI = 15, // Frame Relay DLCI
    ATM = 19, // ATM
    METRICOM = 23, // Metricom STRIP (new IANA id)
    IPSEC = 31 // IPsec tunnel
}; // By gilgil
