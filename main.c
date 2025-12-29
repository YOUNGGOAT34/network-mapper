

#include "nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include "arp_request.h"


/*

  client: socket(),connect(),send(),recv(),close()
*/



int main(i32 argc,const i8 *argv[]) {
  

    if(argc<2) {
        printf("Usage ./main <port range> i.e 2000 3000\n");
        return 0;
    }

    
    i32 start_port=strtol(argv[1],NULL,0);
    i32 end_port=strtol(argv[2],NULL,0);

    //  run(start_port,end_port);
    generate_subnet_ip_addresses();

   
    return 0;

}


