

// #include "nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include "arp_request.h"
#include "hashmap.h"
#include <arpa/inet.h>



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

    if(insert(host)){
       printf("Inserted successfully\n");
    }else{
       printf("Failed to insert\n");
    }

    if(find(ip)){
        printf("Found it \n");
    }else{
       printf("Not found\n");
    }

   
    return 0;

}


