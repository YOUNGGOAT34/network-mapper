#include "hashmap.h"
#include <string.h>
#include <stdio.h>



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

   host->next=table[index];

   table[index]=host;

   return true;

}

HOST *find(i8 *ip){
     u32 index=hash(ip);

     HOST *tmp=table[index];

     while(tmp && strcmp(tmp->string_ip,ip)!=0){
          tmp=tmp->next;
     }

     return tmp;
}

void print_table(){

    for (i32 i=0;i<MAX_TABLE;i++){

         printf("[%d] ",i);
       
         HOST *curr=table[i];
         if(!curr){
             printf(" NULL\n");
             continue;
         }
         while(curr!=NULL){
               printf("%s",curr->string_ip);

              
              if(curr->next){

               printf("--->");
                 
              }

              curr=curr->next;
         }

         printf("\n");
    }

}