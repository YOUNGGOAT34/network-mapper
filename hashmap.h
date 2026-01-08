#ifndef HASHMAP_H
#define HASHMAP_H
#include <stdlib.h>

#define MAX_TABLE 250

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;

typedef struct{

   char ip[MAX_TABLE];
   char *ip_;


}ACTIVE_HOSTS;


u32 hash(char *ip);


#endif