#ifndef ARP_REQUEST_H
#define ARP_REQUEST_H
// #include "nmap.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>


#define RESPONSE_BUFFER 65536
#define ETHERNET_PACKET_lENGTH 42
#define MAC_LENGTH 6
#define IP4_LENGTH 4



#define MAX_HOSTS_BUFFER 1024


typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;


//they are signed by default but making them explicit makes them readable...
typedef  char i8;
typedef signed int i32;


typedef struct {
   i32 front;
   i32 back;
   in_addr_t hosts[MAX_HOSTS_BUFFER];
}alive_hosts_buffer;



u8 *create_raw_ethernet_bytes(in_addr_t *target_ip);
void generate_subnet_ip_addresses();

void initialize_buffer(alive_hosts_buffer* b);
bool push(alive_hosts_buffer* b,in_addr_t *ip);
in_addr_t *pop(alive_hosts_buffer *b);
bool full(alive_hosts_buffer *);
bool empty(alive_hosts_buffer *);
#endif