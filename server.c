#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/select.h>

const int MAX_PACKET_SIZE = 1024;
const int HEADER_SIZE = 24;
const int MAX_PAYLOAD_SIZE = 1000;
const int RTOTime = 500;
const int MAX_SEQ_NUM = 30720;

// For UDP socket programming, the following tutorial was used: https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
// For select(), the following tutorial was used: http://beej.us/guide/bgnet/output/html/multipage/selectman.html

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
int main(int argc, char *argv[])
{
	int port = 2000;

	// Check for correct argument length
	if (argc != 2) {
		fprintf(stderr, "Error: correct usage: ./server <portnumber>.\n");
		exit(1);
	}
	port = atoi(argv[1]);
	struct sockaddr_in serv_addr, cli_addr;
	int sockfd; 
	socklen_t serv_len,cli_len;
	char buffer[MAX_PAYLOAD_SIZE];
	//parameter for the sending message
    int seq_num = 0, wnd = 5120, retrans = 0, syn = 0, fin = 0;
    size_t len = 0;
    unsigned int start = 0;

	if( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		fprintf(stderr, "socket error.\n");
		exit(1);
	}
	



	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);


	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("bind failed");
		exit(-1);
	}
	printf("server listening .....\n");
	while(1){
		while (!syn){
            if( (getPacket(sockfd, buffer, &len, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_len, &seq_num,&wnd, &syn, &fin, &start)) == -1)
                fprintf(stderr, "can't receive syn.\n");
        }
        // debug purpose 
        printf("Client: %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        printf("Receiving packet %i %i syn\n", seq_num, wnd);

	}
	

	

	
}


