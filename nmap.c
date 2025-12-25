#include "nmap.h"
#include <stdio.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>





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



void run(u16 start_port,u16 end_port){
     
}




//ring buffer functions  implementation
void initialize_buffer(buffer* b){
      b->back=-1;
      b->front=-1;
}

bool push(buffer* b,u16 *port){
     if(full(b)){
         fprintf(stderr,"Full buffer\n");
         return false;
     }

     if(b->front==-1){
         b->front=0;
         b->back=0;
     }else{
         b->back=(b->back+1)%MAX_BUFFER;
     }

     b->ports[b->back]=port;
     return true;
}
u16 *pop(buffer *b){
      u16 *port=b->ports[b->front];
      if(b->front==b->back){
          b->front=b->back=-1;
      }else{
         b->front=(b->front+1)%MAX_BUFFER;
      }
       return port;
}
bool full(buffer *b){
     return  (b->front==(b->back+1 )% MAX_BUFFER);
}
bool empty(buffer *b){
     return b->front==-1;
}