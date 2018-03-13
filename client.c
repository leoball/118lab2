
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


int main(int argc, char* argv[]){
    
    int port = 2000;
    int sock_fd;
    struct sockaddr_in serv_addr;

    //parameter for the sending message
    int seq_num = 0, wnd = 5120, retrans = 0, syn = 0, fin = 0;
    unsigned int start = 0;
    char buffer[MAX_PACKET_SIZE];

    
    //get the port number 
    if(argc != 4 ){
        fprintf(stderr,"Error: The correct usage: client <server_hostname> <server_portnumber> <filename>.\n");
        exit(1);
    }
    port = atoi(argv[2]);
    
    //create a socket 
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0){
        fprintf(stderr,"Cannot create socket.\n");
        exit(1);
    }
    //get ip address for the host name 
    struct hostent * server;
    server = gethostbyname(argv[1]);
    if(!server){
        fprintf(stderr, "unfound host.\n");
        exit(1);
    }
    
    memset((char *) &serv_addr, 0, sizeof(serv_addr));//reset memory
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    

    printf("client connecting .... on port:%d\n",port);
    
    
    return 0;
}
