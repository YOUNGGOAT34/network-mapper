

// #include "nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include "arp_request.h"
#include "hashmap.h"
#include <arpa/inet.h>
#include <string.h>



int main(i32 argc,const i8 *argv[]) {


  // port_range *range=malloc(sizeof(port_range));
  

    // if(argc<2) {
    //     printf("Usage ./main <port range> i.e 2000 3000\n");
    //     return 0;
    // }


    
    // i32 start_port=strtol(argv[1],NULL,0);
    // i32 end_port=strtol(argv[2],NULL,0);

    // range->start=start_port;
    // range->end=end_port;

    // generate_subnet_ip_addresses(range);



    struct in_addr int_ip;
    char *ip="192.168.1.1";

    inet_aton(ip,&int_ip);

    HOST *host=malloc(sizeof(HOST));
    host->int_ip=int_ip.s_addr;
    host->string_ip=ip;

    struct in_addr addr;
    char ip_buf[16];

    for (int i = 1; i <= 254; i++) {
        snprintf(ip_buf, sizeof(ip_buf), "192.168.1.%d", i);

        inet_aton(ip_buf, &addr);

        HOST *host = malloc(sizeof(HOST));
        if (!host) {
            perror("malloc");
            return 1;
        }

        host->int_ip = addr.s_addr;
        
        host->string_ip = strdup(ip_buf);  // REQUIRED
        

        insert(host);
    }


    print_table();

   
    return 0;

}


