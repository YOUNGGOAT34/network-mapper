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
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>



typedef struct {
   in_addr_t start_ip;
   in_addr_t end_ip;
   int sock;
   unsigned char mac[6];
   in_addr_t src_ip;
   const char *iface;
} arp_sender_args_t;

typedef struct {
   in_addr_t ip;
   uint16_t port;
} tcp_args_t;



// in_addr_t generate(void);
extern in_addr_t start_ip_address, end_ip_address;

char *network_to_presentation(in_addr_t);
int get_iface_ip_mask(const char *, in_addr_t *, in_addr_t *mask, unsigned char *);
void send_arp_packet(int sock, unsigned char *, in_addr_t , in_addr_t , const char *); 
void *listen_arp_replies(void *);
void compute_subnet_range(in_addr_t , in_addr_t ); 
void *arp_sender_thread(void *) ;
int connection(in_addr_t , uint16_t);
void *tcp_connect_thread(void *); 

