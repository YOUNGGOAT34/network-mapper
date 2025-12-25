

#include "nmap.h"
#include <stdio.h>
#include <stdlib.h>


/*

  client: socket(),connect(),send(),recv(),close()
*/



int main(i32 argc,const u8 *argv[]) {
  

    if(argc<2) {
        printf("Usage ./main <port range> i.e 2000 3000\n");
        return 0;
    }

    
    i32 start_port=strtol(argv[1],NULL,0);
    i32 end_port=strtol(argv[2],NULL,0);

    for (i32 i=start_port;i<end_port;i++){
            connect_to_server(i);
    }

   
    return 0;

}


