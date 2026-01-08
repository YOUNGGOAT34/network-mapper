#ifndef HASHMAP_H
#define HASHMAP_H
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_TABLE 250

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;

typedef struct{

   char *string_ip;
   in_addr_t int_ip;


}HOST;


u32 hash(char *ip);
bool insert(HOST *host);


#endif