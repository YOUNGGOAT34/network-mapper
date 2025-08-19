#ifndef NMAP_H
#define NMAP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>
#include<stdlib.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define PROTOSIZE 4
#define  MACSIZE  6

#define MAXTHREADPOOL 30
#define PORTSPERTASK 100
#define ARPHTYPE_ETHER 1
#define ETHERTYPE_IP 0x0800
#define  ARPOPCODE_REQUEST 1
#define ARPOPCODE_REPLY 2
#define ARP_PROTOCAL 0x0806
#define MAXPORT 65535



typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef uint8_t uint8;
typedef char int8;

extern pthread_t pool[MAXTHREADPOOL];

typedef struct {
   in_addr_t ip;
   uint16_t start_port;
   uint16_t end_port;
} port_range_t;


typedef struct{
     in_addr_t ip;
     uint16 start_port;
     uint16 end_port;
}port_scan_args_t;

typedef struct ether_arp{
     uint16 HTYPE;
     uint16 PTYPE;
     uint8 HLEN;
     uint8 PLEN;
     uint16 OPCODE;
      
     uint8 SHA[MACSIZE];
     uint8 SPA[PROTOSIZE];
     uint8 THA[MACSIZE];
     uint8 TPA[PROTOSIZE];
     

}__attribute__((packed)) ether_arp;

typedef struct ether_header{
    uint8 dst_mac[MACSIZE];
    uint8 src_mac[MACSIZE];
    uint16 ETHER_TYPE;

}__attribute__((packed)) ether_header;


typedef struct {
   in_addr_t start_ip;
   in_addr_t end_ip;
   int sock;
   unsigned char mac[6];
   in_addr_t src_ip;
   const char *iface;
} arp_sender_args_t;


// in_addr_t generate(void);
extern in_addr_t start_ip_address, end_ip_address;
extern pthread_t thread;
int8 *network_to_presentation(in_addr_t);
int get_iface_ip_mask(const char *, in_addr_t *, in_addr_t *mask, unsigned char *);
void send_arp_packet(int sock, unsigned char *, in_addr_t , in_addr_t , const char *); 
void *listen_arp_replies(void *);
void compute_subnet_range(in_addr_t , in_addr_t ); 
void *arp_sender_thread(void *) ;
void* tcp_port_range_scan(void* arg) ;
void* tcp_task_worker(void* arg);

#endif

