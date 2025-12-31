// #ifndef NMAP_H
// #define NMAP_H


// #include<stdbool.h>


// #define MAX_BUFFER 250
// #define NUM_OF_THREADS 10

// typedef unsigned char u8;
// typedef unsigned short int u16;
// typedef unsigned int u32;
// typedef unsigned long int u64;


// //they are signed by default but making them explicit makes them readable...
// typedef  char i8;
// typedef signed int i32;


// typedef struct{
//    u16 start;
//    u16 end;
// }port_range;


// //ring buffer :will havean array of ports to scan ,a circular queue

// typedef struct {
//    i32 front;
//    i32 back;
//     u16 *ports[MAX_BUFFER];
// }buffer;


// void run(u16 start_port,u16 end_port);
// // void connect_to_server(u16 port);

// void initialize_buffer(buffer* b);
// bool push(buffer* b,u16 *port);
// u16 *pop(buffer *b);
// bool full(buffer *);
// bool empty(buffer *);





// #endif

