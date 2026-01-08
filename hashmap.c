#include "hashmap.h"
#include <string.h>



HOST *table[MAX_TABLE];

u32 hash(char *ip){
    u32 hash_value=0;
    u32 len=strlen(ip);

    for(u32 i=0;i<len;i++){
       hash_value+=ip[i];
       hash_value=(hash_value*ip[i])%MAX_TABLE;
    } 
    return hash_value;
}

bool insert(HOST *host){
   
   if(!host) return false;

   u32 index=hash(host->string_ip);

   if(table[index]!=NULL) return false;

   table[index]=host;
   return true;

}

HOST *find(i8 *ip){
     u32 index=hash(ip);

     if(table[index]!=NULL && strcmp(ip,table[index]->string_ip)){
     
        return table[index];
     }

     return NULL;
}