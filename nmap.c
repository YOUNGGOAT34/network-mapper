#include "nmap.h"
#include <stdio.h>
/*
this function will take a network byte order address and convert it to a dotted format string
Don't want to use the inet_ntop() function since this function takes extra parameters and we only need one in this case
*/

pthread_t pool[MAXTHREADPOOL];
pthread_t thread;
in_addr_t start_ip_address, end_ip_address;
port_range_t *task_queue;
int total_tasks;
int current_task = 0;
pthread_mutex_t port_mutex=PTHREAD_MUTEX_INITIALIZER;


int8 *network_to_presentation(in_addr_t ip_address){
   /*
      example: 10.0.0.1
      10-a
      0-b
      0-c
      1-d
   */
   //   uint32_t ip_address=ntohl(ip);
     unsigned char a,b,c,d;
     int8 *string_ip=malloc(INET6_ADDRSTRLEN);
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


void send_arp_packet(int sock, unsigned char *src__mac, in_addr_t src_ip, in_addr_t target_ip, const char *iface) {
   unsigned char buffer[42];
   struct ether_header *eth = (struct ether_header *)buffer;
   struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
   
   memset(eth->dst_mac, 0xff, 6); 
   memcpy(eth->src_mac, src__mac, 6);
   eth->ETHER_TYPE = htons(ARP_PROTOCAL);

   arp->HTYPE=htons(ARPHTYPE_ETHER);
   arp->PTYPE=htons(ETHERTYPE_IP);
   arp->HLEN=MACSIZE;
   arp->PLEN=PROTOSIZE;
   arp->OPCODE=htons(ARPOPCODE_REQUEST);
   

   memcpy(arp->SHA, src__mac, MACSIZE);
   memcpy(arp->SPA, &src_ip, PROTOSIZE);
   memset(arp->THA, 0x00, MACSIZE);
   memcpy(arp->TPA, &target_ip, PROTOSIZE);

   struct sockaddr_ll socket_address = {0};
   socket_address.sll_family = AF_PACKET;
   socket_address.sll_ifindex = if_nametoindex(iface);
   socket_address.sll_halen = 6;
   memset(socket_address.sll_addr, 0xff, 6);
   sendto(sock, buffer, 42, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
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
       if (ntohs(eth->ETHER_TYPE) != ARP_PROTOCAL) continue;

       struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
       if (ntohs(arp->OPCODE) != ARPOPCODE_REPLY) continue;

       char ip_str[INET_ADDRSTRLEN];
       inet_ntop(AF_INET, arp->SPA, ip_str, sizeof(ip_str));

       printf("Host found: %s with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
              ip_str,
              arp->SHA[0], arp->SHA[1], arp->SHA[2],
              arp->SHA[3], arp->SHA[4], arp->SHA[5]);

              in_addr_t ip;
              inet_pton(AF_INET, ip_str, &ip);
   


            
           
            total_tasks=(MAXPORT+PORTSPERTASK-1)/PORTSPERTASK;
            port_range_t *tasks=malloc(sizeof(port_range_t)*total_tasks);
            task_queue=tasks;

           
            int port=1;

            for(int i=0;i<total_tasks;i++){
                tasks[i].start_port=port;
                tasks[i].end_port=port+PORTSPERTASK-1;
                tasks[i].ip=ip;
                if(tasks[i].end_port > MAXPORT){
                    tasks[i].end_port=MAXPORT;
                }

                port+=PORTSPERTASK;

               
            }
             
            for(int i=0;i<MAXTHREADPOOL;i++){
                 pthread_create(&pool[i],NULL,tcp_task_worker,NULL);
            }
            
          
      
      
   }

   return NULL;
}


void* tcp_task_worker(void* arg) {
   while (1) {
       pthread_mutex_lock(&port_mutex);
       if (current_task >= total_tasks) {
           pthread_mutex_unlock(&port_mutex);
           break;
       }

       port_range_t task = task_queue[current_task++];
       pthread_mutex_unlock(&port_mutex);

       tcp_port_range_scan(&task);
   }

   return NULL;
}

//try tcp connection on different ports to find open ports

void* tcp_port_range_scan(void* arg) {
   port_range_t* range = (port_range_t*)arg;
   in_addr_t ip = range->ip;

   for (uint16_t port = range->start_port; port <= range->end_port; port++) {
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       if (sockfd < 0) continue;

       struct sockaddr_in addr;
       addr.sin_family = AF_INET;
       addr.sin_port = htons(port);
       addr.sin_addr.s_addr = ip;

       struct timeval timeout = {0, 100000};
       setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
       setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
       
       printf("scanning port: %d\n",port);
       int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
       close(sockfd);

       if (result == 0) {
           int8* ip_str = network_to_presentation(ip);
           printf("PORT %d open on IP: %s\n", port, ip_str);
           free(ip_str);
       }
   }

 
   return NULL;
}




void *arp_sender_thread(void *arg){
   arp_sender_args_t *args = (arp_sender_args_t *)arg;
   for (in_addr_t ip = args->start_ip;
        ntohl(ip) <= ntohl(args->end_ip);
        ip = htonl(ntohl(ip) + 1)) {
       send_arp_packet(args->sock, args->mac, args->src_ip, ip, args->iface);
       usleep(10000); 
   }
   free(arg);
   return NULL;
}