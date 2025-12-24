

#include "nmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>


/*

  client: socket(),connect(),send(),recv(),close()
*/

void connect_to_server(u16 port){

    struct sockaddr_in server_address;
    
    memset(&server_address,0,sizeof(server_address));
    
    server_address.sin_family=AF_INET;
    server_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    server_address.sin_port=htons(port);

    i32 sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0){
         fprintf(stderr,"Failed to create remote socket\n");
         exit(EXIT_FAILURE);
    }

    i32 connect_status=connect(sockfd,(struct sockaddr *)&server_address,sizeof(server_address));
    
    if(connect_status==0){
          printf("Port open\n");
    }else{
         if(errno==ECONNREFUSED){
             printf("Port closed\n");
         }else{
             printf("Port filtered : (%s)\n",strerror(errno));
         }
    }

    close(sockfd);

     
}



int main(i32 argc,const u8 *argv[]) {
  

    if(argc<2) {
        printf("Usage ./main <port range> i.e 2000 3000\n");
        return 0;
    }

    
    i32 start_port=strtol(argv[1],NULL,0);
    // i32 end_port=strtol(argv[2],NULL,0);

    connect_to_server(start_port);





    
    return 0;

}


