
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include<arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include<stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <inttypes.h>
#include <semaphore.h>
#include "arp_request.h"



/*
   for each alive hosts we scan a range of ports as given by the user
   A port iterator:

        current_port=shows which port is being scanned at the moment
        start port=where scanning starts
        end port=where scanning ends
*/


bool done_scanning=false;


alive_hosts_buffer *hosts_buffer;



u16 start_port;
u16 end_port;
u16 current_port;


pthread_mutex_t bufferMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t currentPortMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t scanCond=PTHREAD_COND_INITIALIZER;



sem_t  buffer_empty,buffer_full;



in_addr_t current_ip_address;//ip address of this machine
in_addr_t current_alive_ip;//the address being scanned currently
in_addr_t start_ip_address;
in_addr_t current_ip;//for looping through the addresses
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




void compute_subnet_range() {
   start_ip_address = current_ip_address & subnet_mask;
   end_ip_address = start_ip_address | ~subnet_mask;
   start_ip_address = (ntohl(start_ip_address));
   end_ip_address =(ntohl(end_ip_address) - 1);

}



//for the current ip ,send a tcp connection to a port to check if it is open ,increment the current port

void *connect_to_server(void *arg){

    
    (void)arg;

   
    while(true){



        i32 sockfd=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in server_address;
        memset(&server_address,0,sizeof(server_address));
    


        pthread_mutex_lock(&currentPortMutex);
        while(current_port>end_port && !done_scanning){
            pthread_cond_wait(&scanCond,&currentPortMutex);
        }

       if(done_scanning){
           pthread_mutex_unlock(&currentPortMutex);
           close(sockfd);
           break;
       };
         
        u16 port=current_port++;


        
        pthread_mutex_unlock(&currentPortMutex);
        
        server_address.sin_family=AF_INET;
        server_address.sin_addr.s_addr=(current_alive_ip);
        server_address.sin_port=htons(port);
         
       
        if(sockfd<0){
             fprintf(stderr,"Failed to create remote socket\n");
             exit(EXIT_FAILURE);
        }
    
        i32 connect_status=connect(sockfd,(struct sockaddr *)&server_address,sizeof(server_address));
        
        if(connect_status==0){
              printf("Port open %"PRIu16 "\n",port);
        }else{
             if(errno!=ECONNREFUSED){
                 printf("Port filtered : (%s)\n",strerror(errno));
             }
           
        }

         close(sockfd);
    
    }


    return NULL;


     
}



void *scan_ports_in_range(void *arg){
    /*
    
      get the current ip,
      create an address
      spawn threads to connect to ports of this ip in a given range
    */

    port_range *range=(port_range *)arg;
   
    while(true){

        if(empty(hosts_buffer) && done_scanning){
            
             pthread_cond_broadcast(&scanCond);
             pthread_mutex_unlock(&bufferMutex);
             break;

        }

        sem_wait(&buffer_full);
        pthread_mutex_lock(&bufferMutex);
        current_alive_ip=pop(hosts_buffer);
        
        start_port=range->start;
        end_port=range->end;
        current_port=start_port;
       
        
        pthread_cond_broadcast(&scanCond);
        sem_post(&buffer_empty);
        pthread_mutex_unlock(&bufferMutex);         
    }

    return NULL;
}




void *send_arp_requests(void *arg){

    i32 sockfd=*(i32 *)arg;


    struct ifreq ifrr;
    memset(&ifrr,0,sizeof(ifrr));

    strncpy(ifrr.ifr_name,"wlan0",IFNAMSIZ);

    if(ioctl(sockfd,SIOCGIFINDEX,&ifrr)<0){
        fprintf(stderr,"Error getting the interface index %s\n",strerror(errno));
        return NULL;
    }

    i32 if_index=ifrr.ifr_ifindex;

    struct sockaddr_ll addr={0};

    addr.sll_family=AF_PACKET;
    addr.sll_halen=ETH_ALEN;
    addr.sll_ifindex=if_index;
    addr.sll_protocol=htons(ETH_P_ARP);

    //bind the socket to wlan0 interface(avoids listening on all interfaces)
    if(bind(sockfd,(struct sockaddr *)&addr,sizeof(addr))<0){
        fprintf(stderr,"Error Binding to wlan0 interface %s\n",strerror(errno));
        return NULL;
    }
  
    memset(addr.sll_addr,0xff,MAC_LENGTH);
     


    while(true){

        
        
        if(current_ip>end_ip_address){
            break;
        }
        in_addr_t target_ip=htonl(current_ip++);

       
            u8 *raw_arp_bytes=create_raw_ethernet_bytes(&target_ip);

    
            ssize_t sent_bytes=sendto(sockfd,raw_arp_bytes,ETHERNET_PACKET_lENGTH,0,(struct sockaddr *)&addr,sizeof(addr));

            if(sent_bytes<0){
                fprintf(stderr,"Error sending arp packet %s\n",strerror(errno));
                free(raw_arp_bytes);
              
                  break;

            }


        free(raw_arp_bytes);
   
        
    }
  
    return NULL;
    
}


void *listen_for_arp_replies(void *arg){
      i32 sockfd=*(i32 *)arg;

       u8 response_buffer[RESPONSE_BUFFER];

        fd_set fds;
        struct timeval tv;

        u8 count=0;

       while(true){

            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);

            tv.tv_sec = 1;
            tv.tv_usec = 0; 


            int select_result = select(sockfd + 1, &fds, NULL, NULL, &tv);

            //if there is nothing for 5 seconds exit this thread

            if(select_result==0){
                if(count==3){
                    done_scanning=true;
                    sem_post(&buffer_full);
                    break;
                }
                count+=1;
                
                continue;
            }

            count=0;

            if(select_result<0){
                 fprintf(stderr,"Select error: %s",strerror(errno));
                 break;
            }

            ssize_t len = recv(sockfd,response_buffer, sizeof(response_buffer), 0);

            if (len < 0) {

            fprintf(stderr,"Errro receiving ARP reply: %s\n",strerror(errno));
            break;
        }

        struct ethhdr *eth = (struct ethhdr *)response_buffer;

        if (ntohs(eth->h_proto) != ETH_P_ARP){
                continue;
        }

      struct arphdr *arp =(struct arphdr *)(response_buffer + sizeof(struct ethhdr));
     
    if (ntohs(arp->ar_op) != ARPOP_REPLY){
        continue;

     }


    /* payload */
    u8 *payload = response_buffer+ sizeof(struct ethhdr) + sizeof(struct arphdr);

    u8 *sha = payload;
    u8 *spa = sha + MAC_LENGTH;
    u8 *tha = spa + IP4_LENGTH;
    u8 *tpa = tha + MAC_LENGTH;

    //check if the response was intended for this machine

    if(memcmp(tpa,&current_ip_address,IP4_LENGTH)!=0){
         continue;
    }

    u32 spa_;
    memcpy(&spa_,spa,IP4_LENGTH);

    
    //check if the arp response comes from the host within the range
    if(ntohl(spa_)<start_ip_address || ntohl(spa_)>end_ip_address){
            continue;
    }

    struct in_addr ip;
    memcpy(&ip, spa, IP4_LENGTH);

    sem_wait(&buffer_empty);
    pthread_mutex_lock(&bufferMutex);
    push(hosts_buffer,&ip.s_addr);
    sem_post(&buffer_full);
    pthread_mutex_unlock(&bufferMutex);


    printf("Host found ,ip: %s | MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
        inet_ntoa(ip),
        sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]
    );

       }

      return NULL;
}



void generate_subnet_ip_addresses(port_range *range){

    hosts_buffer=malloc(sizeof(alive_hosts_buffer));
    initialize_buffer(hosts_buffer);

    sem_init(&buffer_empty,0,MAX_HOSTS_BUFFER);
    sem_init(&buffer_full,0,0);

    i32 sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));


    if(sockfd<0){
            fprintf(stderr,"error creating a socket %s\n",strerror(errno));
            
                return;
            }

    if(get_interface_ip_mask()!=0){
         fprintf(stderr,"Error retrieving interface's subnet mask,mac address and ip address :(%s)\n",strerror(errno));
         return ;
     }

    compute_subnet_range();

    
       current_ip=start_ip_address;

      
        pthread_t threads[20];

        for(i32 i=0;i<10;i++){
             if(i<2){

                 if(i%2==0){
   
                     pthread_create(&threads[i],NULL,&send_arp_requests,&sockfd);
                 }else{
                       pthread_create(&threads[i],NULL,&listen_for_arp_replies,&sockfd);
                 }
             }else{
                   
                   if(i==4){
                       pthread_create(&threads[i],NULL,&scan_ports_in_range,range);
                   }else{

                       pthread_create(&threads[i],NULL,&connect_to_server,NULL);
                   }
             }
        }

        for(i32 i=0;i<10;i++){
              pthread_join(threads[i],NULL);
        }


         free(range);
          close(sockfd);
        
}


u8* create_raw_ethernet_bytes(in_addr_t *target_ip){


    u8 *ethernet_buffer=malloc(ETHERNET_PACKET_lENGTH);
     
   //from the buffer's 42 bytes :first 14 are for ethernet header ,the following 8 are for arp header, and the rest payload 20 payload
     struct ethhdr *ethernet_header=(struct ethhdr *)ethernet_buffer;
     struct arphdr *arp_header=(struct arphdr *)(ethernet_buffer+sizeof(struct ethhdr));

     /*
         ethernet header needs : 
               destination mac-->always broadcast for arp
               source mac
               protocol :ETH_P_ARP(ARP protocol) in this case(must be in network byte order)
     */



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




//ring buffer functions  implementation
void initialize_buffer(alive_hosts_buffer* b){
      b->back=-1;
      b->front=-1;
}

bool push(alive_hosts_buffer* b,in_addr_t *ip){
     if(full(b)){
         fprintf(stderr,"Full buffer\n");
         return false;
     }

     if(b->front==-1){
         b->front=0;
         b->back=0;
     }else{
         b->back=(b->back+1)%MAX_HOSTS_BUFFER;
     }

     b->hosts[b->back]=*ip;
     return true;
}

in_addr_t pop(alive_hosts_buffer *b){
      in_addr_t ip=ip=b->hosts[b->front];
      if(b->front==b->back){
          b->front=b->back=-1;
      }else{
         b->front=(b->front+1)%MAX_HOSTS_BUFFER;
      }
       return ip;
}

bool full(alive_hosts_buffer *b){
     return  (b->front==(b->back+1 )% MAX_HOSTS_BUFFER);
}
bool empty(alive_hosts_buffer *b){
     return b->front==-1;
}