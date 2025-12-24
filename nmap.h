#ifndef NMAP_H
#define NMAP_H


#include<stdbool.h>

typedef char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;


//they are signed by default but making them explicit makes them readable...
typedef signed char i8;
typedef signed int i32;

bool create_connection(void);


#endif

