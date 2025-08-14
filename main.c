

#include "nmap.h"


#define ARP_SENDER_THREADS 10
#define INTERFACE "wlan0"


int main() {
  


    in_addr_t ip, mask;
    unsigned char mac[6];
    
    if (get_iface_ip_mask(INTERFACE, &ip, &mask, mac) == -1) {
        fprintf(stderr, "get_iface_ip_mask failed: %s\n", strerror(errno));
        return 1;
    }
    compute_subnet_range(ip, mask);
    char ip_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    inet_ntop(AF_INET, &mask, mask_str, sizeof(mask_str));

    int8 *start_ip=network_to_presentation(start_ip_address);
    int8 *end_ip=network_to_presentation(end_ip_address);

    printf("Interface IP: %s\n", ip_str);
    printf("Netmask:      %s\n", mask_str);
    printf("Host range:   %s - %s\n",start_ip,end_ip);

   free(start_ip);
   free(end_ip);

    int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ARP_PROTOCAL));
    if (arp_sock < 0) {
        perror("socket");
        return 1;
    }
       
    pthread_t arp_listener;
    pthread_create(&arp_listener, NULL, listen_arp_replies, (void *)(uintptr_t)arp_sock);
     
    

    in_addr_t total_hosts = ntohl(end_ip_address) - ntohl(start_ip_address) + 1;
    in_addr_t hosts_per_thread = total_hosts / ARP_SENDER_THREADS;
    
    pthread_t sender_threads[ARP_SENDER_THREADS];
    
    for (int i = 0; i < ARP_SENDER_THREADS; i++) {
        arp_sender_args_t *args = malloc(sizeof(arp_sender_args_t));
        args->sock = arp_sock;
        args->src_ip = ip;
        memcpy(args->mac, mac, 6);
        args->iface = INTERFACE;
    
        in_addr_t start = ntohl(start_ip_address) + i * hosts_per_thread;
        in_addr_t end = (i == ARP_SENDER_THREADS - 1)
            ? ntohl(end_ip_address)
            : start + hosts_per_thread - 1;
    
        args->start_ip = htonl(start);
        args->end_ip = htonl(end);
    
        pthread_create(&sender_threads[i], NULL, arp_sender_thread, args);
    }


    
   for (int i = 0; i < ARP_SENDER_THREADS; i++) {
      pthread_join(sender_threads[i], NULL);
  }


          
    for (int i = 0; i < MAXTHREADPOOL; i++) {
            pthread_join(pool[i], NULL);
        }


   

   
    pthread_cancel(arp_listener);
    pthread_join(arp_listener, NULL);
    close(arp_sock);
     
    return 0;
}




//bandit0-1:bandit0
//bandit1:password ,ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
//bandit2:263JGJPfgU6LtdEvgfWU1XP5yac29mFx
//bandit3:MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
//bandit4:2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
//bandit5:4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
//banidt6:HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
//bandit7:morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
//bandit8:dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
//bandit9:4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
//bandit10:FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
//bandit11:dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
//bandit12:7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
//banidit13:FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
//bandit15:8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
//bandit16:kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
