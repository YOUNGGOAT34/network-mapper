#include "hashmap.h"
#include <string.h>



u32 hash(char *ip){
    u32 hash_value=0;
    u32 len=strlen(ip);

    for(u32 i=0;i<len;i++){
       hash_value+=ip[i];
       hash_value=(hash_value*ip[i])%MAX_TABLE;
    } 
    return hash_value;
}