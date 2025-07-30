#include "nmap.h"
#include <stdio.h>
/*
   this function will take a network byte order address and convert it to a dotted format string
   Don't want to use the inet_ntop() function since this function takes extra parameters and we only need one in this case
*/
char *network_to_presentation(in_addr_t ip_address){
   /*
      example: 10.0.0.1
      10-a
      0-b
      0-c
      1-d
   */
      
     unsigned char a,b,c,d;
     static char string_ip[16];
     a=((ip_address & 0xff000000) >> 24);
     b=((ip_address & 0x00ff0000)>>16);
     c=((ip_address & 0x0000ff00)>>8);
     d=(ip_address & 0x000000ff);
     memset(string_ip,0,16);
     sprintf(string_ip,"%d.%d.%d.%d",d,c,b,a);
    
     return string_ip;

}
