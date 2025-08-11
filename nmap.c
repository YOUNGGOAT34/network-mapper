#include "nmap.h"
#include <stdio.h>
/*
   this function will take a network byte order address and convert it to a dotted format string
   Don't want to use the inet_ntop() function since this function takes extra parameters and we only need one in this case
*/

in_addr_t start_ip_address, end_ip_address;

char *network_to_presentation(in_addr_t ip_address){
   /*
      example: 10.0.0.1
      10-a
      0-b
      0-c
      1-d
   */
   //   uint32_t ip_address=ntohl(ip);
     unsigned char a,b,c,d;
     char *string_ip=malloc(INET6_ADDRSTRLEN);
     a=((ip_address & 0xff000000) >> 24);
     b=((ip_address & 0x00ff0000)>>16);
     c=((ip_address & 0x0000ff00)>>8);
     d=(ip_address & 0x000000ff);
     memset(string_ip,0,16);
     snprintf(string_ip,INET6_ADDRSTRLEN,"%u.%u.%u.%u",d,c,b,a);
    
     return string_ip;

}


void compute_subnet_range(in_addr_t ip, in_addr_t mask) {
   start_ip_address = ip & mask;
   end_ip_address = start_ip_address | ~mask;
   start_ip_address = htonl(ntohl(start_ip_address) + 1);
   end_ip_address = htonl(ntohl(end_ip_address) - 1);
}



int get_iface_ip_mask(const char *iface, in_addr_t *ip, in_addr_t *mask, unsigned char *mac) {
   int fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0) return -1;

   struct ifreq if_request;
   strncpy(if_request.ifr_name,iface, IFNAMSIZ);

   // Get IP
   if (ioctl(fd, SIOCGIFADDR, &if_request) < 0) return -1;
   *ip = ((struct sockaddr_in *)&if_request.ifr_addr)->sin_addr.s_addr;

   // Get Netmask
   if (ioctl(fd, SIOCGIFNETMASK, &if_request) < 0) return -1;
   *mask = ((struct sockaddr_in *)&if_request.ifr_netmask)->sin_addr.s_addr;

   // Get MAC
   if (ioctl(fd, SIOCGIFHWADDR, &if_request) < 0) return -1;
   memcpy(mac, if_request.ifr_hwaddr.sa_data, 6);

   close(fd);
   return 0;
}


void send_arp_packet(int sock, unsigned char *src_mac, in_addr_t src_ip, in_addr_t target_ip, const char *iface) {
   unsigned char buffer[42];
   struct ether_header *eth = (struct ether_header *)buffer;
   struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));

   memset(eth->ether_dhost, 0xff, 6); 
   memcpy(eth->ether_shost, src_mac, 6);
   eth->ether_type = htons(ETHERTYPE_ARP);

   arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
   arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
   arp->ea_hdr.ar_hln = 6;
   arp->ea_hdr.ar_pln = 4;
   arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

   memcpy(arp->arp_sha, src_mac, 6);
   memcpy(arp->arp_spa, &src_ip, 4);
   memset(arp->arp_tha, 0x00, 6);
   memcpy(arp->arp_tpa, &target_ip, 4);

   struct sockaddr_ll sll = {0};
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = if_nametoindex(iface);
   sll.sll_halen = 6;
   memset(sll.sll_addr, 0xff, 6);

   sendto(sock, buffer, 42, 0, (struct sockaddr *)&sll, sizeof(sll));
}



void *listen_arp_replies(void *arg) {
   int sock = (int)(uintptr_t)arg;
   pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
   pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

   unsigned char buffer[65536];
   while (1) {
       pthread_testcancel();

       int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
       if (len < 0) continue;

       struct ether_header *eth = (struct ether_header *)buffer;
       if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;

       struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
       if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) continue;

       char ip_str[INET_ADDRSTRLEN];
       inet_ntop(AF_INET, arp->arp_spa, ip_str, sizeof(ip_str));

       printf("Host found: %s at MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
              ip_str,
              arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
              arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

              in_addr_t ip;
              inet_pton(AF_INET, ip_str, &ip);
      
              // Launch TCP connect thread
              tcp_args_t *args = malloc(sizeof(tcp_args_t));
              args->ip = ip;
            //   args->port = PORT;
      
              pthread_t t;
              pthread_create(&t, NULL, tcp_connect_thread, args);
              pthread_detach(t);
   }

   return NULL;
}

//try tcp connection on different ports to find open ports
void *tcp_connect_thread(void *arg) {
   tcp_args_t *args = (tcp_args_t *)arg;
   in_addr_t ip = args->ip;
   free(args); // Free early since we don't reuse it
   uint16_t ports[] = {
      22, 53, 67, 68, 80, 88, 123, 137, 138, 139,
      443, 445, 554, 8000, 8080, 8888, 9000
  };
   size_t port_count = sizeof(ports) / sizeof(ports[0]);

   for (size_t i = 0; i < port_count; i++) {
       if (connection(ip, ports[i])) {
           printf("Port %d open on %s\n", ports[i], network_to_presentation(ip));
       }
   }
   return NULL;
}




int connection(in_addr_t ip, uint16_t port) {
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) return 0;

   struct sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   addr.sin_addr.s_addr = ip;

   // Set timeout for connect
   struct timeval timeout;
   timeout.tv_sec = 1;
   timeout.tv_usec = 0;
   setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
   setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

   int result = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
   close(sockfd);

   return result == 0;
}




void *arp_sender_thread(void *arg){
   arp_sender_args_t *args = (arp_sender_args_t *)arg;
   for (in_addr_t ip = args->start_ip;
        ntohl(ip) <= ntohl(args->end_ip);
        ip = htonl(ntohl(ip) + 1)) {
       send_arp_packet(args->sock, args->mac, args->src_ip, ip, args->iface);
       usleep(10000);  // Optional: reduce or remove for speed
   }
   free(arg);
   return NULL;
}