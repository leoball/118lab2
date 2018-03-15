
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#define MSG_200 "HTTP/1.1 200 OK\r\n"
#define ERROR_404 "<h1>Error 404: File Not Found Under Working Directory!</h1>"

const int HEADER_SIZE = 24;
const int MAX_PACKET_SIZE = 1024;
const int MAX_PAYLOAD_SIZE = 1000;
const int RETRANS_TIME = 500;
#define ACK 'a'
#define RETRANS 'r'
#define DATA 'd'

struct packet
{
    int type;
    //0:
    //1:data
    //2:ack
    //3:retrans
    int fin;
    //0: disabled
    //1: error
    //2: EOF

    int seq;
    //sequence number
    int msg_404;
    int max_seq;
    char* data_buff[MAX_PAYLOAD_SIZE];
    double time;
    int size;
    int seq_count; 
};



// message is the payload bytes, and len is the length of the payload bytes
int sendPacket(int sockfd, char* message, size_t len, const struct sockaddr *dest_addr, socklen_t dest_len, int seqNum, int wnd, int syn, int fin, unsigned int fileStart)
{

    int result = -1;

    int packetLen = HEADER_SIZE + len;

    // Payload too large
    if (packetLen > MAX_PACKET_SIZE)
        return -1;

    char* toSend = malloc(packetLen);
    bzero(toSend, packetLen);

    int intSize = sizeof(int);

    // Copy in the header information
    memcpy(toSend, &len, intSize);
    memcpy(toSend + intSize, &seqNum, intSize);
    memcpy(toSend + intSize * 2, &wnd, intSize);
    memcpy(toSend + intSize * 3, &syn, intSize);
    memcpy(toSend + intSize * 4, &fin, intSize);
    memcpy(toSend + intSize * 5, &fileStart, intSize);
    memcpy(toSend + HEADER_SIZE, message, len);
    fprintf(stderr, "%c\n",toSend[10] );
    result = sendto(sockfd, toSend, packetLen, 0, dest_addr, dest_len);
    if (result < 0)
    {
        perror("sendto failed.");
        free(toSend);
        return -1;
    }

    free(toSend);

    return result;
}

// Wrapper function for recvfrom that also gets the header contents from the packet and copies them into the corresponding parameters
int getPacket(int sockfd, char* message, size_t* len, struct sockaddr *src_addr, socklen_t * src_len, int* seqNum, int* wnd, int* syn, int* fin, unsigned int* fileStart)
{

    int result = -1;
    int packetLen = MAX_PACKET_SIZE;

    char* received = malloc(packetLen);
    bzero(received, packetLen);
    bzero(message, packetLen);


    result = recvfrom(sockfd, received, packetLen, 0, src_addr, src_len);

    int intSize = sizeof(int);
    
    memcpy(len, received, intSize);
    memcpy(seqNum, received + intSize, intSize);
    memcpy(wnd, received + intSize*2, intSize);
    memcpy(syn, received + intSize*3, intSize);
    memcpy(fin, received + intSize*4, intSize);
    memcpy(fileStart, received + intSize*5, intSize);
    memcpy(message, received + HEADER_SIZE, MAX_PAYLOAD_SIZE);

    free(received);

    return result;
}

int check_time_out(int sock_fd){
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock_fd, &read_fds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RETRANS_TIME * 1000;
    int i = 0;
    if((i = select(sock_fd + 1, &read_fds, NULL, NULL, &tv)) == 0)
        return 1;
    else
        return 0;

}


int main(int argc, char* argv[]){
    
    int port = 2000;
    char* filename;
    FILE *file_fd;
    int sock_fd;
    struct sockaddr_in serv_addr;
    socklen_t serv_len;

    //parameter for the sending message
    int seq_num = 0, wnd = 5120, retrans = 0, syn = 0, fin = 0;
    size_t len = 0;
    unsigned int start = 0;
    char buffer[MAX_PACKET_SIZE];

    
    //get the port number 
    if(argc != 4 ){
        fprintf(stderr,"Error: The correct usage: client <server_hostname> <server_portnumber> <filename>.\n");
        exit(1);
    }
    port = atoi(argv[2]);
    filename = argv[3];
    
    //create a socket 
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0){
        fprintf(stderr,"Cannot create socket.\n");
        exit(1);
    }
    //get ip address for the host name 
    struct hostent * server = NULL;
    server = gethostbyname(argv[1]);
    
    if(server == NULL){
        fprintf(stderr, "unfound host.\n");
        exit(1);
    }
    fprintf(stderr, "%s\n",server-> h_addr_list[1]);

    
    memset((char *) &serv_addr, 0, sizeof(serv_addr));//reset memory
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_len = sizeof(serv_addr);

    printf("client connecting .... on port:%d\n",port);
    // the syn part 
    int ret = 0;
    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
    //do the syn
    //fd_set read_fds;
    //we set ret equals 2 when successfully receive message from syn
    while(ret != 2){
        //send syn packet 
        if((sendPacket(sock_fd,buffer,0,(struct sockaddr *)&serv_addr,serv_len,0,wnd,1,0,0)) == -1){
            fprintf(stderr, "send packet error.\n");
            exit(1);
        }

        if(!ret)
            fprintf(stdout, "Sending packet SYN\n");
        else
            fprintf(stdout, "Sending packet Retransmission SYN\n");

        if (check_time_out(sock_fd)){
            fprintf(stderr, "packet timeout.\n");
            ret = 1;
        }
        else{
            int i = 0;
            if((i = getPacket(sock_fd,buffer,&len,(struct sockaddr *)&serv_addr,&serv_len,&seq_num,&wnd,&syn,&fin,&start)) == -1){
                fprintf(stderr, "getPacket error\n");
                ret = 1;
            }
            else{
                if(!seq_num && !len && syn){
                    ret = 2;
                    printf("Receiving packet SYN-ACK\n");
                }
                else{
                     fprintf(stderr, "error: Did not receive expected SYN-ACK.");
                     ret = 1;

                }
            }

        }

        

    }
    //send the file name to the server
    ret = 0;
Packet_filename:
    while(ret != 2){
        bzero(buffer,MAX_PACKET_SIZE);
        sprintf(buffer, "%s", argv[3]);
        if((sendPacket(sock_fd,buffer,strlen(buffer),(struct sockaddr *)&serv_addr,serv_len,0,wnd,0,0,0)) == -1){
            fprintf(stderr, "send packet error.\n");
            exit(1);
        }
         if(!ret)
            fprintf(stdout, "Sending packet 0\n");
         else
            fprintf(stdout, "Sending packet 0 Retransmission\n");
        ret = 2;

        if (check_time_out(sock_fd)){
            fprintf(stderr, "packet timeout.\n");
            ret = 1;
        }
        
        if( (file_fd = fopen("received.data", "w")) == 0){
            fprintf(stderr, "%s\n","failed to create received.data");
            exit(1);
        }


    }

    int window_size = wnd/MAX_PACKET_SIZE;

    printf("Requested %s from %s.\n", argv[3], argv[1]);
    printf("Propagating...\n");

    struct packet data_packet;
    memset((char*) &data_packet, 0, sizeof(data_packet));

    data_packet.fin = 0;
    data_packet.seq = 0;
    data_packet.type = 2;

    struct packet* window;
    window = (struct packet*) malloc(window_size * sizeof(struct packet));
    int x;
    for (x=0; x<window_size; x++)
    {
        memset(&(window[i]), -1, sizeof(struct packet));
    }
    int window_start = 0;
    int window_end = window_start + window_size;

    char* suffix = "";
    while(1)
    {
        recvfrom(sock_fd, &data_packet, sizeof(data_packet), 0, (struct sockaddr*) &serv_addr, &serv_len);
        if (data_packet.msg_404 == 1)
        {
            printf("404 NOT FOUND\n");
            //goto fin------------------------------------------------------------------
        }

        if (data_packet.fin == 1)
            suffix = "FIN";
        if (data_packet.type == 3)
            suffix = "Retransmission";
        printf("Receiving packet %d\n", data_packet.seq);

        if (window_end > data_packet.max_seq)
            window_end = data_packet.max_seq;
        else
            window_end = window_size;


        int curr_seq = (data_packet.seq + data_packet.seq_count*30720)/MAX_PAYLOAD_SIZE;
        if ((curr_seq - window_start >= 0) && (curr_seq - window_start < window_size))
        {
            struct packet ack_packet;
            memset((char*) &ack_packet, 0, sizeof(ack_packet));
            ack_packet.type = 2;
            ack_packet.seq = data_packet.seq;
            ack_packet.seq_count = data_packet.seq_count;
            sendto(sock_fd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr*) &serv_addr, &serv_len);
            printf("Sending packet %d %s\n", ack_packet.seq, suffix);

            memcpy( &(window[curr_seq - window_start]), &data_packet, sizeof(struct data_packet));

            while(1){
                if ((window[0].seq + window[0].seq_count * 30720) / MAX_PAYLOAD_SIZE == window_start)
                {
                    fwrite(window[0].data_buff, sizeof(char), window[0].size, file_fd);
                    int i = 0;
                    for (i = 0; i != window_size - 1; i++)
                    {
                        memcpy(&(window[i]), &(window[i+1]), sizeof(struct packet));
                    }
                    memset(&(window[window_size-1]), -1, sizeof(struct packet)):
                    window_start += 1;
                }
                else
                    break;
            }

        }
    }


    /*

    //start file transfer process
    while(!fin){
        int i = 0;
         if((i = getPacket(sock_fd,buffer,&len,(struct sockaddr *)&serv_addr,&serv_len,&seq_num,&wnd,&syn,&fin,&start)) == -1){
                fprintf(stderr, "getPacket error\n");
                ret = 1;
            }
        bzero(buffer, MAX_PACKET_SIZE);
        if(start == -1){
            fprintf(stderr, "%s\n","404 NOT FOUND\n");
            exit(1);
        }
       


    }*/

    
    return 0;
}
