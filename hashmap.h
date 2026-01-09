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

typedef char i8;
typedef int i32;

typedef struct HOST{

   i8 *string_ip;
   in_addr_t int_ip;

   struct HOST *next;

}HOST;


u32 hash(char *ip);
bool insert(HOST *host);
HOST *find(i8 *);
void print_table();


#endif