#include "nmap.h"
#include <stdio.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>





buffer *_buffer;

bool done_scanning=false;

pthread_mutex_t buffer_mutex;
pthread_cond_t buffer_full_cond;//not necessarily full,but there is data inside the buffer
pthread_cond_t buffer_empty_cond;//not necessarily empty,but there is a space inside the buffer

//producer
void *add_port_to_buffer(void *arg){
    
     port_range *range=(port_range *)arg;

      for(u16 i=range->start;i<range->end;i++){
              u16 *port=malloc(sizeof(u16));
              *port=i;
              pthread_mutex_lock(&buffer_mutex);
              while(full(_buffer)){
                 pthread_cond_wait(&buffer_empty_cond,&buffer_mutex);
              }

              push(_buffer,port);

              pthread_cond_signal(&buffer_full_cond);
              pthread_mutex_unlock(&buffer_mutex);
      }

      pthread_mutex_lock(&buffer_mutex);

      printf("Done\n");

      

      done_scanning=true;

      pthread_cond_broadcast(&buffer_full_cond);
      pthread_mutex_unlock(&buffer_mutex);

      return NULL;
}

//consumer
void *connect_to_server(void *arg){


    (void)arg;

   

    while(true){

        i32 sockfd=socket(AF_INET,SOCK_STREAM,0);

        pthread_mutex_lock(&buffer_mutex);

        while(empty(_buffer) && !done_scanning){
             pthread_cond_wait(&buffer_full_cond,&buffer_mutex);
        }
   

        if(empty(_buffer) && done_scanning){
            pthread_mutex_unlock(&buffer_mutex);
            break;
        }

        u16 *port=pop(_buffer);
       
        pthread_cond_signal(&buffer_empty_cond);
        pthread_mutex_unlock(&buffer_mutex);

        struct sockaddr_in server_address;
        
        memset(&server_address,0,sizeof(server_address));
    
    
        
        server_address.sin_family=AF_INET;
        server_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        server_address.sin_port=htons(*port);
         
       
        if(sockfd<0){
             fprintf(stderr,"Failed to create remote socket\n");
             exit(EXIT_FAILURE);
        }
    
        i32 connect_status=connect(sockfd,(struct sockaddr *)&server_address,sizeof(server_address));
        
        if(connect_status==0){
              printf("Port open%"PRIu16 "\n",*port);
        }else{
             if(errno==ECONNREFUSED){
                
             }else{
                 printf("Port filtered : (%s)\n",strerror(errno));
             }
        }

        free(port);
         close(sockfd);
    
        
    }


   
    
    return NULL;


     
}




void run(u16 start_port,u16 end_port){

       _buffer=malloc(sizeof(buffer));
       initialize_buffer(_buffer);



       pthread_mutex_init(&buffer_mutex,NULL);
       pthread_cond_init(&buffer_full_cond,NULL);
       pthread_cond_init(&buffer_empty_cond,NULL);
      


       port_range *range=malloc(sizeof(port_range));
       range->start=start_port;
       range->end=end_port;

       pthread_t threads[NUM_OF_THREADS];

       for(i32 i=0;i<NUM_OF_THREADS;i++){
             if(i==0){
                 pthread_create(&threads[i],NULL,&add_port_to_buffer,range);
             }else{
                 pthread_create(&threads[i],NULL,&connect_to_server,NULL);
             } 
       }


       for(i32 i=0;i<NUM_OF_THREADS;i++){
            pthread_join(threads[i],NULL);
       }

     
       
       
       pthread_mutex_destroy(&buffer_mutex);
       pthread_cond_destroy(&buffer_empty_cond);
       pthread_cond_destroy(&buffer_full_cond);


      return ;

       
}




//ring buffer functions  implementation
void initialize_buffer(buffer* b){
      b->back=-1;
      b->front=-1;
}

bool push(buffer* b,u16 *port){
     if(full(b)){
         fprintf(stderr,"Full buffer\n");
         return false;
     }

     if(b->front==-1){
         b->front=0;
         b->back=0;
     }else{
         b->back=(b->back+1)%MAX_BUFFER;
     }

     b->ports[b->back]=port;
     return true;
}
u16 *pop(buffer *b){
      u16 *port=b->ports[b->front];
      if(b->front==b->back){
          b->front=b->back=-1;
      }else{
         b->front=(b->front+1)%MAX_BUFFER;
      }
       return port;
}
bool full(buffer *b){
     return  (b->front==(b->back+1 )% MAX_BUFFER);
}
bool empty(buffer *b){
     return b->front==-1;
}