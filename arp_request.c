
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include<arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include<stdio.h>
#include "arp_request.h"



    in_addr_t current_ip_address;//ip address of this machine
    in_addr_t start_ip_address;
    in_addr_t end_ip_address;
    in_addr_t subnet_mask;//subnet mask of the interface
    u8 mac_address[MAC_LENGTH];//mac address of this machine


i32 get_interface_ip_mask() {

   i32 fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0) return -1;
   
   struct ifreq if_request;
   strncpy(if_request.ifr_name,"wlan0", IFNAMSIZ);

   // Get IP
   if (ioctl(fd, SIOCGIFADDR, &if_request) < 0) return -1;
   current_ip_address = ((struct sockaddr_in *)&if_request.ifr_addr)->sin_addr.s_addr;
    
   // Get Netmask
   if (ioctl(fd, SIOCGIFNETMASK, &if_request) < 0) return -1;
   subnet_mask = ((struct sockaddr_in *)&if_request.ifr_netmask)->sin_addr.s_addr;

   //get my mac address
   if(ioctl(fd,SIOCGIFHWADDR,&if_request)<0) return -1;
   memcpy(mac_address,if_request.ifr_hwaddr.sa_data,MAC_LENGTH);
   

   close(fd);
   return 0;
}




u8 *print_ip(u32 ip){
    ip=ntohl(ip);
    u8 *str=malloc(16);
    if(!str){
        //  error("Failed to allocate memory for the IP return string\n");
    }
    snprintf(str,16,"%u.%u.%u.%u",
      (ip>>24) & 0xFF,
      (ip>>16) & 0xFF,
      (ip>>8) & 0xFF,
       ip & 0xFF
    );

    return str;
}



void compute_subnet_range() {
   start_ip_address = current_ip_address & subnet_mask;
   end_ip_address = start_ip_address | ~subnet_mask;
   start_ip_address = (ntohl(start_ip_address));
   end_ip_address =(ntohl(end_ip_address) - 1);

   // range *r=malloc(sizeof(range));
   // r->start=(start_ip_address);
   // r->end=(end_ip_address);
   // return r;
}


void generate_subnet_ip_addresses(){
    get_interface_ip_mask();
    compute_subnet_range();

    in_addr_t current_ip=start_ip_address;

    
    
        printf("start: %s\n",print_ip(htonl(start_ip_address)));
        printf("end ip %s\n",print_ip(htonl(end_ip_address)));
        printf("current ip %s\n",print_ip(htonl(current_ip)));
        // current_ip+=1;
        // printf("current ip %s\n",print_ip(htonl(current_ip)));
        // return;
       
        while(true){

          
           
            current_ip+=1;
             printf("%s\n",print_ip(htonl(current_ip)));


              if(current_ip>end_ip_address){
                break;
              }
        }
    

}

u8* create_raw_ethernet_bytes(in_addr_t *target_ip){
    
    u8 *ethernet_buffer=malloc(ETHERNET_PACKET_lENGTH);
     

    

   //from the buffer's 42 bytes :first 14 are for ethernet header ,the following 28 are for arp header, and the rest payload
     struct ethhdr *ethernet_header=(struct ethhdr *)ethernet_buffer;
     struct arphdr *arp_header=(struct arphdr *)(ethernet_buffer+sizeof(struct ethhdr));

     /*
         ethernet header needs : 
               destination mac-->always broadcast for arp
               source mac
               protocol :ETH_P_ARP(ARP protocol) in this case(must be in network byte order)
     */

     if(get_interface_ip_mask()!=0){
         fprintf(stderr,"Error retrieving interface's subnet mask,mac address and ip address\n");
         return NULL;
     }

     memset(ethernet_header->h_dest,0xff,MAC_LENGTH);
     memcpy(ethernet_header->h_source,mac_address,MAC_LENGTH);
     ethernet_header->h_proto=htons(ETH_P_ARP);



     /*
         arp header needs:
               Hardware type
               protocol type
               Hardware address length(mac address length:6 bytes)
               Protocol address length(length of IPv4 address :4 bytes)
               Operation(is it an arp request or an arp reply??)
     */

     arp_header->ar_hrd=htons(ARPHRD_ETHER);
     arp_header->ar_pro=htons(ETH_P_IP);
     arp_header->ar_hln=MAC_LENGTH;
     arp_header->ar_pln=IP4_LENGTH;
     arp_header->ar_op=htons(ARPOP_REQUEST);

     //payload
     /*
      memory layout of the payload:

          sender hardware address(SHA)-->48 bits(6 bytes)
          Sender IP (SPA)-->32 bits (4 bytes)
          Target MAC (THA)-->48 bits (6 bytes)
          Target IP (TPA)--32 bits (4 bytes)
     
     */


     u8 *payload_ptr=ethernet_buffer+sizeof(struct ethhdr)+sizeof(struct arphdr);

     u8 *sha=payload_ptr;
     u8 *spa=sha+MAC_LENGTH;
     u8 *tha=spa+IP4_LENGTH;
     u8 *tpa=tha+MAC_LENGTH;

     memcpy(sha,mac_address,MAC_LENGTH);
     memcpy(spa,&current_ip_address,IP4_LENGTH);
     memset(tha,0x00,MAC_LENGTH);
     memcpy(tpa,target_ip,IP4_LENGTH);


   return ethernet_buffer;
   
}