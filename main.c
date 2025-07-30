#include<stdio.h>
#include "nmap.h"
#include<unistd.h>
#include <sys/socket.h>
in_addr_t start_p_address,end_ip_address;
bool end_of_range=false;
uint16_t PORT;
//if the ip addresses are not given ,I wanna take them in from the stdi
in_addr_t generate(void){
     if(start_p_address >= end_ip_address){
        end_of_range=true;
        return (in_addr_t)-1;
     }

          
      start_p_address++;

      return start_p_address;
}

//tcp connect
bool connection(in_addr_t ip_address,uint16_t port_no){
   struct sockaddr_in sock;
   int fd,connection_status;

   fd=socket(AF_INET,SOCK_STREAM,0);

   if(fd<1) exit(1);

   sock.sin_family=AF_INET;
   sock.sin_port=htons(port_no);
   sock.sin_addr.s_addr=ip_address;
   
   connection_status=connect(fd,(struct sockaddr *)&sock,sizeof(sock));
   //if connection status is not 0 then the connection did not go through
   if(connection_status){
       close(fd);
       return false;
   }

   //if the program gets here ,the connection was successful
   char buffer[256];
   memset(buffer,0,sizeof(buffer));
   uint16_t i=recv(fd,buffer,sizeof(buffer),0);
    if(i<2) printf("%s\n",network_to_presentation(ip_address));
    else{
        i--;
        char *p=buffer+i;
        if(*p=='\n' || *p=='\r'){
          *p=0;

          printf("ip: %s, header: %s\n",network_to_presentation(ip_address),buffer);
        }
    }
   return true;



}



int main(int argc,char *argv[]){

   if(argc>2){
      
       start_p_address=inet_addr(argv[2]);

       //17042745
   }
   if(argc>3){
        end_ip_address=inet_addr(argv[3]);
   }

   PORT=(uint16_t)strtol(argv[1],NULL,0);

   while(!end_of_range){
      in_addr_t addr=generate();
      printf("here\n");
      connection(addr,PORT);
   }


   return 0;
}