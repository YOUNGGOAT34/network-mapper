

// #include "nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include "arp_request.h"



int main(i32 argc,const i8 *argv[]) {


  port_range *range=malloc(sizeof(port_range));
  

    if(argc<2) {
        printf("Usage ./main <port range> i.e 2000 3000\n");
        return 0;
    }


    
    i32 start_port=strtol(argv[1],NULL,0);
    i32 end_port=strtol(argv[2],NULL,0);

    range->start=start_port;
    range->end=end_port;

    generate_subnet_ip_addresses(range);

   
    return 0;

}


