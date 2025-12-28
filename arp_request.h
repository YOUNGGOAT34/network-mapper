#ifndef ARP_REQUEST_H
#define ARP_REQUEST_H
#include "nmap.h"

#define ETHERNET_PACKET_lENGTH 42
#define MAC_LENGTH 6
#define IP4_LENGTH 4






// u8 *create_raw_ethernet_bytes(in_addr_t *target_ip);
void generate_subnet_ip_addresses();
#endif