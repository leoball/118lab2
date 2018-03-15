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
const int RETRANS_TIME = 500;
const int MAX_SEQ_NUM = 30720;
#define ERROR_404 "Error 404: File Not Found Under Working Directory!\n"

// For UDP socket programming, the following tutorial was used: https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
// For select(), the following tutorial was used: http://beej.us/guide/bgnet/output/html/multipage/selectman.html

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

int sendPacket(int sockfd, char* message, size_t len, const struct sockaddr *dest_addr, socklen_t dest_len, int seqNum, int wnd, int syn, int fin, unsigned int fileStart)
{

    int result = -1;

    int packetLen = HEADER_SIZE + len;

    // Payload too large
    if (packetLen > MAX_PACKET_SIZE)
        return -1;

    char* toSend = malloc(packetLen);
    bzero(toSend, packetLen);
   

    

    // Copy in the header information
    memcpy(toSend, &len, sizeof(int));
    memcpy(toSend + sizeof(int), &seqNum, sizeof(int));
    memcpy(toSend + sizeof(int) * 2, &wnd, sizeof(int));
    memcpy(toSend + sizeof(int) * 3, &syn, sizeof(int));
    memcpy(toSend + sizeof(int) * 4, &fin, sizeof(int));
    memcpy(toSend + sizeof(int) * 5, &fileStart, sizeof(int));
    memcpy(toSend + HEADER_SIZE, message, len);

    result = sendto(sockfd, toSend, packetLen, 0, dest_addr, dest_len);

    if (result < 0){
       	fprintf(stderr, "%s\n","sendto error." );
        free(toSend);
        return -1;
    }

    free(toSend);

    return result;
}

// Wrapper function for recvfrom that also gets the header contents from the packet and copies them into the corresponding parameters
int getPacket(int sock_fd, char* message, size_t* len, struct sockaddr *src_addr, socklen_t * src_len, int* seqNum, int* wnd, int* syn, int* fin, unsigned int* fileStart){

	int result = -1;
	int packetLen = MAX_PACKET_SIZE;

	char* received = malloc(packetLen);
	bzero(received, packetLen);
	bzero(message, packetLen);


	result = recvfrom(sock_fd, received, packetLen, 0, src_addr, src_len);
	 if (result < 0){
       	fprintf(stderr, "%s\n","receive error." );
        free(received);
        return -1;
    }

	
	memcpy(len, received, sizeof(int));
	memcpy(seqNum, received + sizeof(int), sizeof(int));
	memcpy(wnd, received + sizeof(int)*2, sizeof(int));
	memcpy(syn, received + sizeof(int)*3, sizeof(int));
	memcpy(fin, received + sizeof(int)*4, sizeof(int));
	memcpy(fileStart, received + sizeof(int)*5, sizeof(int));
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
	int sock_fd; 
	socklen_t serv_len,cli_len;
	FILE *file_fd;
	
	char buffer[MAX_PAYLOAD_SIZE];
	//parameter for the sending message
    int seq_num = 0, wnd = 5120, retrans = 0, syn = 0, fin = 0;
    size_t len = 0;
    unsigned int start = 0;

	if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		fprintf(stderr, "socket error.\n");
		exit(1);
	}

	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);


	if ( (bind(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0) {
		perror("bind failed");
		exit(-1);
	}
	cli_len = sizeof(cli_addr);
	serv_len = sizeof(serv_addr);
	
	//return the new server sock_fd
	if ((getsockname(sock_fd, (struct sockaddr *)&serv_addr, &serv_len)) < 0) {
		fprintf(stderr, "%s\n","failed to return the new sock_fd" );
		return -1;
	}
	printf("server listening .....\n");
	
	while(1){
		while (!syn){
            if( (getPacket(sock_fd, buffer, &len, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_len, &seq_num,&wnd, &syn, &fin, &start)) == -1)
                fprintf(stderr, "can't receive syn.\n");
        }
        // debug purpose 
        printf("Client: %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        printf("Receiving packet %i %i syn\n", seq_num, wnd);

        
        int synack = 0;
        
        // the synack process, get the file name at last  
        int ret = 0;
        while(1){
        	printf("Client: %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
        	if(sendPacket(sock_fd,buffer,0,(struct sockaddr *) &cli_addr,cli_len,seq_num,wnd,1,0,0) == -1){
        		fprintf(stderr, "%s\n","SYN-ACK sending error." );
        		exit(1);
        	}

        	else{
        		if(ret)
        			printf("Sending packet %d %d Retransmission SYN-ACK\n", seq_num, wnd);
                else
                    printf("Sending packet %d %d SYN-ACK\n", seq_num, wnd);

        	}
            if (check_time_out(sock_fd)){
                fprintf(stderr, "packet timeout.\n");
                ret = 1;
            }
        	else
        		break;


        }
        //receive the filename 
        if( (getPacket(sock_fd, buffer, &len, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_len, &seq_num,&wnd, &syn, &fin, &start)) == -1)
                fprintf(stderr, "can't receive filename.\n");
        else{
        	if((file_fd = fopen(buffer,"r")) == NULL){
        		sendPacket(sock_fd,ERROR_404,0,(struct sockaddr *) &cli_addr,cli_len,seq_num,wnd,0,1,-1);
        		

        	}
        }

	}
	

	

	
}


