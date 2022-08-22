#include <stdint.h>
#pragma pack(push, 1)
typedef struct{
    uint8_t Dst_mac[6];
    uint8_t Src_mac[6];
    uint16_t type;
}EthHdr;
#pragma pack(pop)

enum: uint16_t {
    Ip4 = 0x0800,
    Arp = 0x0806,
    Ip6 = 0x86DD
}; // By gilgil
