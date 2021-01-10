/*Name: Yen Pham
CS3530
Project 4 - Simulate TCP 3-way handshake and closing a TCP connection in the application layer 
using a client-server architecture.
*/

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <wchar.h>
#include <time.h> 
#include <math.h>
#include "TCP_segment.h"

int portnum;

void client_close_TCP_connection(int socket_fd, struct tcp_seg *TCP_segment)
{
	bool error_check = false;
	unsigned short int temp_checksum;
	FILE *fp;
	fp = fopen("client.out", "a"); //append mode

	//Get client port number
	struct sockaddr_in local_addr;
	int addr_size = sizeof(local_addr);
	getsockname(socket_fd, (struct sockaddr *) &local_addr, &addr_size);

	//printf("client port: %d\n", ntohs(local_addr.sin_port));
	
	TCP_segment->srcport = ntohs(local_addr.sin_port);
	TCP_segment->destport = portnum;

	unsigned int temp_seqnum = TCP_segment->seqnum;
	TCP_segment->seqnum = TCP_segment->acknum; //Assign a 1024 as client sequence number
	TCP_segment->acknum = temp_seqnum + 1; //Assign acknowledgement number as 512
	int header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
	TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
	TCP_segment->reserved = 0;
	TCP_segment->urg = 0;
	TCP_segment->ack = 0;
	TCP_segment->psh = 0;
	TCP_segment->rst = 0;
	TCP_segment->syn = 0;
	TCP_segment->fin = 1; //Set the FIN bit to 1
	TCP_segment->window = 0;
	TCP_segment->checksum = 0;
	TCP_segment->pointer = 0;
	TCP_segment->option = 0;
	memset(TCP_segment->data, 0, 128);

	//Calculate checksum
	unsigned short int checksum_arr[76];
	unsigned int sum=0, checksum, wrap;

	memcpy(checksum_arr, TCP_segment, 24); //Copying 24 bytes

	for (int i=0;i<12;i++)
	{
		//printf("0x%04X\n", checkksum_arr[i]);
		sum = sum + checksum_arr[i];
	}

	wrap = sum >> 16;// Wrap around once  
	sum = sum & 0x0000FFFF;   
	sum = wrap + sum;  
	wrap = sum >> 16;// Wrap around once more  
	sum = sum & 0x0000FFFF;  
	checksum = wrap + sum;  
	//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
	//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

	TCP_segment->checksum = checksum;
	int length = write(socket_fd, TCP_segment, 24);//send message to server
	if (length <= 0)
	{
		printf("Client failed to send FIN signal to close TCP connection\n");
	}
	else
	{
		printf("\nClient has succesfully sent FIN signal to server to request closing of TCP connection\n");
		printf("TCP source port: %d\n", TCP_segment->srcport);
		printf("TCP destination port: %d\n", TCP_segment->destport);
		printf("TCP sequence number: %d\n", TCP_segment->seqnum);
		printf("TCP ack number: %d\n", TCP_segment->acknum);
		printf("TCP offset/ header length: %d\n", TCP_segment->offset);
		printf("TCP URG bit value: %d\n", TCP_segment->urg);
		printf("TCP ACK bit value: %d\n", TCP_segment->ack);
		printf("TCP PSH bit value: %d\n", TCP_segment->psh);
		printf("TCP RST bit value: %d\n", TCP_segment->rst);
		printf("TCP SYN bit value: %d\n", TCP_segment->syn);
		printf("TCP FIN bit value: %d\n", TCP_segment->fin);
		printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);

		//Print values to file client.out
		fprintf(fp, "\nServer has sent SYN ACK signal to client succesfully\n");
		fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
		fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
		fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
		fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
		fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
		fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
		fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
		fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
		fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
		fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
		fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
		fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
	}

	//Receive ACK message from server 
	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	int rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	
	if (rec_bytes > 0)
	{
		printf("\nClient received ACK signal from server\n");
		
		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr1[76];
		sum=0;
		checksum=0;
		wrap=0;

		memcpy(checksum_arr1, TCP_segment, 152); //Copying 24+128 bytes

		for (int i=0;i<76;i++)
		{
			//printf("0x%04X\n", checkksum_arr1[i]);
			sum = sum + checksum_arr1[i];
		}

		wrap = sum >> 16;// Wrap around once  
		sum = sum & 0x0000FFFF;   
		sum = wrap + sum;  
		wrap = sum >> 16;// Wrap around once more  
		sum = sum & 0x0000FFFF;  
		checksum = wrap + sum;  
		//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
		//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

		TCP_segment->checksum = temp_checksum;
		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				error_check = true;
				//Print values
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				printf("Checksum check: good. Bits check: good\n");

				fprintf(fp, "\nClient received ACK signal from server\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
			}
			else
			{
				printf("Error: ACK bit from TCP segment is incorrect\n");
			}		
		}
		else
		{
			printf("Error! Checksum of TCP segment are incorrect\n");
		}
	}

	//After receiving ACK message from server. The client gets TCP segment from server with FIN signal.
	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	if (rec_bytes > 0)
	{
		printf("\nClient received FIN signal from server\n");
		
		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr2[76];
		sum=0;
		checksum=0;
		wrap=0;

		memcpy(checksum_arr2, TCP_segment, 152); //Copying 24+128 bytes

		for (int i=0;i<76;i++)
		{
			//printf("0x%04X\n", checkksum_arr1[i]);
			sum = sum + checksum_arr2[i];
		}

		wrap = sum >> 16;// Wrap around once  
		sum = sum & 0x0000FFFF;   
		sum = wrap + sum;  
		wrap = sum >> 16;// Wrap around once more  
		sum = sum & 0x0000FFFF;  
		checksum = wrap + sum;  
		//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
		//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

		error_check = false;
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->fin == 1)
			{
				error_check = true;
				//Print values
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				printf("Checksum check: good. Bits check: good\n");

				fprintf(fp, "\nClient received FIN signal from server\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
			}
			else
			{
				printf("Error: FIN bit from TCP segment is incorrect\n");
			}		
		}
		else
		{
			printf("Error! Checksum of TCP segment are incorrect\n");
		}

		if (error_check)
		{
			TCP_segment->srcport = ntohs(local_addr.sin_port);
			TCP_segment->destport = portnum;
			temp_seqnum = TCP_segment->seqnum;
			TCP_segment->seqnum = TCP_segment->acknum;
			TCP_segment->acknum = temp_seqnum + 1; //Acknowledgement number equal to server sequence number + 1
			TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
			TCP_segment->reserved = 0;
			TCP_segment->urg = 0;
			TCP_segment->ack = 1; //Set the ACK bit to 1
			TCP_segment->psh = 0;
			TCP_segment->rst = 0;
			TCP_segment->syn = 0;
			TCP_segment->fin = 0;
			TCP_segment->window = 0;
			TCP_segment->checksum = 0;
			TCP_segment->pointer = 0;
			TCP_segment->option = 0;
			memset(TCP_segment->data, 0, 128);

			//Calculate checksum
			unsigned short int checksum_arr1[12];
			sum=0; checksum = 0; wrap = 0;

			memcpy(checksum_arr1, TCP_segment, 24); //Copying 24 bytes

			for (int i=0;i<12;i++)
			{
				//printf("0x%04X\n", checkksum_arr[i]);
				sum = sum + checksum_arr1[i];
			}

			wrap = sum >> 16;// Wrap around once  
			sum = sum & 0x0000FFFF;   
			sum = wrap + sum;  
			wrap = sum >> 16;// Wrap around once more  
			sum = sum & 0x0000FFFF;  
			checksum = wrap + sum;  
			//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
			//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

			TCP_segment->checksum = checksum;
			length = write(socket_fd, TCP_segment, 24);//send message to server
			if (length <= 0)
			{
				printf("Client failed to send ACK signal to close TCP connection\n");
			}
			else
			{
				//Print values
				printf("\nClient has succesfully sent ACK signal to server to close TCP connection\n");
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);

				//Print values to file client.out
				fprintf(fp, "\nClient has succesfully sent ACK signal to server to close TCP connection\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
			}
		}
	}
	fclose(fp);
	free(TCP_segment);

}


void client_three_way_handshake(int socket_fd, char* buffer, size_t buffer_length)
{
	bool connection_created = false;
	struct tcp_seg *TCP_segment; //Create a connection request TCP segment
	TCP_segment = malloc(sizeof(struct tcp_seg));
	FILE *fp;
	fp = fopen("client.out", "w"); //write mode

	//Get client port number
	struct sockaddr_in local_addr;
	int addr_size = sizeof(local_addr);
	getsockname(socket_fd, (struct sockaddr *) &local_addr, &addr_size);

	printf("Server port: %d\n", portnum);
	printf("Client port: %d\n", ntohs(local_addr.sin_port));
	
	TCP_segment->srcport = ntohs(local_addr.sin_port);
	TCP_segment->destport = portnum;

	//srand(time(NULL));
	TCP_segment->seqnum = rand()% (int) (pow(2,32));
	unsigned int temp_seqnum = TCP_segment->seqnum;
	TCP_segment->acknum = 0;
	int header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
	TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
	TCP_segment->reserved = 0;
	TCP_segment->urg = 0;
	TCP_segment->ack = 0;
	TCP_segment->psh = 0;
	TCP_segment->rst = 0;
	TCP_segment->syn = 1; //Set the SYN bit to 1
	TCP_segment->fin = 0;
	TCP_segment->window = 0;
	TCP_segment->checksum = 0;
	TCP_segment->pointer = 0;
	TCP_segment->option = 0;
	memset(TCP_segment->data, 0, 128);

	//Calculate checksum
	unsigned short int checksum_arr[76];
	unsigned int sum=0; 
	unsigned int checksum =0;
	unsigned int wrap = 0;

	memcpy(checksum_arr, TCP_segment, 152); //Copying 24+128 bytes

	for (int i=0;i<76;i++)
	{
		//printf("0x%04X\n", checkksum_arr[i]);
		sum = sum + checksum_arr[i];
	}

	wrap = sum >> 16;// Wrap around once  
	sum = sum & 0x0000FFFF;   
	sum = wrap + sum;  
	wrap = sum >> 16;// Wrap around once more  
	sum = sum & 0x0000FFFF;  
	checksum = wrap + sum;  
	//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
	//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

	TCP_segment->checksum = checksum;
	int length = send(socket_fd, TCP_segment, sizeof(struct tcp_seg), 0);//send message to server

	if (length <= 0)
	{
		printf("Fail to send SYN signal to request connection\n");
	}
	else
	{
		//Print values
		printf("\nClient has succesfully sent SYN signal to request connection\n");
		printf("TCP source port: %d\n", TCP_segment->srcport);
		printf("TCP destination port: %d\n", TCP_segment->destport);
		printf("TCP sequence number: %d\n", TCP_segment->seqnum);
		printf("TCP ack number: %d\n", TCP_segment->acknum);
		printf("TCP offset/ header length: %d\n", TCP_segment->offset);
		printf("TCP URG bit value: %d\n", TCP_segment->urg);
		printf("TCP ACK bit value: %d\n", TCP_segment->ack);
		printf("TCP PSH bit value: %d\n", TCP_segment->psh);
		printf("TCP RST bit value: %d\n", TCP_segment->rst);
		printf("TCP SYN bit value: %d\n", TCP_segment->syn);
		printf("TCP FIN bit value: %d\n", TCP_segment->fin);
		printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);

		//Print values to file client.out
		fprintf(fp, "\nClient has succesfully sent SYN signal to request connection\n");
		fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
		fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
		fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
		fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
		fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
		fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
		fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
		fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
		fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
		fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
		fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
		fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
	}

	bool error_check = false;
	unsigned short int temp_checksum;
	//Receive ACK SYN message from server
	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	int rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	if (rec_bytes > 0)
	{
		printf("\nClient received SYN ACK signal from server\n");
		
		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr1[76];
		sum=0;
		checksum=0;
		wrap=0;

		memcpy(checksum_arr1, TCP_segment, 152); //Copying 24+128 bytes

		for (int i=0;i<76;i++)
		{
			//printf("0x%04X\n", checkksum_arr1[i]);
			sum = sum + checksum_arr1[i];
		}

		wrap = sum >> 16;// Wrap around once  
		sum = sum & 0x0000FFFF;   
		sum = wrap + sum;  
		wrap = sum >> 16;// Wrap around once more  
		sum = sum & 0x0000FFFF;  
		checksum = wrap + sum;  
		//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
		//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

		TCP_segment->checksum = temp_checksum;
		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1 && TCP_segment->syn == 1)
			{
				error_check = true;
				//Print values
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				printf("Checksum check: good. Bits check: good\n");

				fprintf(fp, "\nClient received SYN ACK signal from server\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
			}
			else
			{
				printf("Error: SYN ACK bits from TCP segment are incorrect\n");
			}		
		}
		else
		{
			printf("Error! Checksum of TCP segment are incorrect\n");
		}

		if (error_check) //start preparing tcp segment to send back ack signal
		{
			//The client responds back with an acknowledgement TCP segment.
			TCP_segment->srcport = ntohs(local_addr.sin_port);
			TCP_segment->destport = portnum;
			TCP_segment->acknum = TCP_segment->seqnum + 1; //Acknowledgement number equal to initial server sequence number + 1
			TCP_segment->seqnum = temp_seqnum + 1; //Assign a sequence number as initial client sequence number + 1
			TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
			TCP_segment->reserved = 0;
			TCP_segment->urg = 0;
			TCP_segment->ack = 1; //Set the ACK bit to 1
			TCP_segment->psh = 0;
			TCP_segment->rst = 0;
			TCP_segment->syn = 0;
			TCP_segment->fin = 0;
			TCP_segment->window = 0;
			TCP_segment->checksum = 0;
			TCP_segment->pointer = 0;
			TCP_segment->option = 0;			
			memset(TCP_segment->data, 0, 128);
			memcpy(TCP_segment->data, buffer, 128);

			unsigned short int checksum_arr2[76];
			sum=0; 
			checksum = 0; 
			wrap = 0;
			memcpy(checksum_arr2, TCP_segment, 152); //Copying 24 bytes
			for (int i=0;i<76;i++)
			{
				//printf("0x%04X\n", checkksum_arr2[i]);
				sum = sum + checksum_arr2[i];
			}

			wrap = sum >> 16;// Wrap around once  
			sum = sum & 0x0000FFFF;   
			sum = wrap + sum;  
			wrap = sum >> 16;// Wrap around once more  
			sum = sum & 0x0000FFFF;  
			checksum = wrap + sum;  
			//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
			//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

			TCP_segment->checksum = checksum;
			length = write(socket_fd, TCP_segment, 152);//send message to server
			
			
			if (length <= 0)
			{
				printf("Fail to send ACK signal to request connection\n");
			}
			else
			{
				printf("\nClient has succesfully sent ACK signal to sever\n");
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				printf("Client's text file: %s\n", buffer);
				printf("Data sent to server(128 bytes): %s\n", TCP_segment->data);

				//Print values to file client.out
				fprintf(fp, "\nServer has sent SYN ACK signal to client succesfully\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				fprintf(fp, "Text file: %s\n", buffer);
				fprintf(fp, "Data chunk sent to server: %s\n", TCP_segment->data);
			}
		}
	}

	//After connection is created and the first 128 bytes of data were sent to server, wait for the ACK signal from server

	size_t send_length = 128;
	int n = 1;

	do
	{
		memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
		rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
		if (rec_bytes > 0)
		{
			printf("\nClient received ACK signal from server\n");
		
			//Calculate checksum to check if the segment is error free
			temp_checksum = TCP_segment->checksum;
			TCP_segment->checksum = 0;
			unsigned short int checksum_arr1[76];
			sum=0;
			checksum=0;
			wrap=0;

			memcpy(checksum_arr1, TCP_segment, 152); //Copying 24+128 bytes

			for (int i=0;i<76;i++)
			{
				//printf("0x%04X\n", checkksum_arr1[i]);
				sum = sum + checksum_arr1[i];
			}

			wrap = sum >> 16;// Wrap around once  
			sum = sum & 0x0000FFFF;   
			sum = wrap + sum;  
			wrap = sum >> 16;// Wrap around once more  
			sum = sum & 0x0000FFFF;  
			checksum = wrap + sum;  
			//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
			//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));
	
			error_check = false;
			TCP_segment->checksum = temp_checksum;
			if (checksum == TCP_segment->checksum)
			{
				if (TCP_segment->ack == 1)
				{
					error_check = true;
					//Print values
					printf("\nClient received ACK signal from server\n");
					printf("TCP source port: %d\n", TCP_segment->srcport);
					printf("TCP destination port: %d\n", TCP_segment->destport);
					printf("TCP sequence number: %d\n", TCP_segment->seqnum);
					printf("TCP ack number: %d\n", TCP_segment->acknum);
					printf("TCP offset/ header length: %d\n", TCP_segment->offset);
					printf("TCP URG bit value: %d\n", TCP_segment->urg);
					printf("TCP ACK bit value: %d\n", TCP_segment->ack);
					printf("TCP PSH bit value: %d\n", TCP_segment->psh);
					printf("TCP RST bit value: %d\n", TCP_segment->rst);
					printf("TCP SYN bit value: %d\n", TCP_segment->syn);
					printf("TCP FIN bit value: %d\n", TCP_segment->fin);
					printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
					printf("Checksum check: good. Bits check: good\n");
	
					fprintf(fp, "\nClient received ACK signal from server\n");
					fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
					fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
					fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
					fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
					fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
					fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
					fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
					fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
					fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
					fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
					fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
					fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				}
				else
				{
					printf("Error: ACK bit from TCP segment is incorrect\n");
				}		
			}
			else
			{
				printf("Error! Checksum of TCP segment are incorrect\n");
			}

			if (error_check) //start preparing tcp segment to send back ack signal & next data chunk
			{
				//The client responds back with an acknowledgement TCP segment & next data
				send_length = send_length + 128;
				TCP_segment->srcport = ntohs(local_addr.sin_port);
				TCP_segment->destport = portnum;
				temp_seqnum = TCP_segment->seqnum;
				TCP_segment->seqnum = TCP_segment->acknum; //sequence number equal to the received acknowledgement number from the server
				TCP_segment->acknum = temp_seqnum + 1;
				TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
				if (send_length < buffer_length)
				{
					TCP_segment->reserved = 0;
				}
				else
				{
					TCP_segment->reserved = 1;
				}
				TCP_segment->urg = 0;
				TCP_segment->ack = 1; //Set the ACK bit to 1
				TCP_segment->psh = 0;
				TCP_segment->rst = 0;
				TCP_segment->syn = 0;
				TCP_segment->fin = 0;
				TCP_segment->window = 0;
				TCP_segment->checksum = 0;
				TCP_segment->pointer = 0;
				TCP_segment->option = 0;			
				memset(TCP_segment->data, 0, 128);
				memcpy(TCP_segment->data, buffer+ n*128, 128);
				n++;

				unsigned short int checksum_arr2[76];
				sum=0; 
				checksum = 0; 
				wrap = 0;
				memcpy(checksum_arr2, TCP_segment, 152); //Copying 24 bytes
				for (int i=0;i<76;i++)
				{
					//printf("0x%04X\n", checkksum_arr2[i]);
					sum = sum + checksum_arr2[i];
				}

				wrap = sum >> 16;// Wrap around once  
				sum = sum & 0x0000FFFF;   
				sum = wrap + sum;  
				wrap = sum >> 16;// Wrap around once more  
				sum = sum & 0x0000FFFF;  
				checksum = wrap + sum;  
				//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
				//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));

				TCP_segment->checksum = checksum;
				length = write(socket_fd, TCP_segment, 152);//send message to server
				if (length <= 0)
				{
					printf("Fail to send ACK signal\n");
				}
				else
				{
					printf("\nClient has succesfully sent ACK signal to sever\n");
					printf("TCP source port: %d\n", TCP_segment->srcport);
					printf("TCP destination port: %d\n", TCP_segment->destport);
					printf("TCP sequence number: %d\n", TCP_segment->seqnum);
					printf("TCP ack number: %d\n", TCP_segment->acknum);
					printf("TCP offset/ header length: %d\n", TCP_segment->offset);
					printf("TCP URG bit value: %d\n", TCP_segment->urg);
					printf("TCP ACK bit value: %d\n", TCP_segment->ack);
					printf("TCP PSH bit value: %d\n", TCP_segment->psh);
					printf("TCP RST bit value: %d\n", TCP_segment->rst);
					printf("TCP SYN bit value: %d\n", TCP_segment->syn);
					printf("TCP FIN bit value: %d\n", TCP_segment->fin);
					printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
					//printf("Client's text file: %s\n", buffer);
					printf("Data chunk sent to server: %s\n", TCP_segment->data);

					//Print values to file client.out
					fprintf(fp, "\nServer has sent SYN ACK signal to client succesfully\n");
					fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
					fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
					fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
					fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
					fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
					fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
					fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
					fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
					fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
					fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
					fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
					fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
					fprintf(fp, "Text file: %s\n", buffer);
					fprintf(fp, "Data chunk sent to server: %s\n", TCP_segment->data);
				}
			}
		}
	} while (send_length < buffer_length);

	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));

	if (rec_bytes > 0)
	{
		printf("\nClient received ACK signal from server. All data chunks have been sent succesfully\n");
		
		//Calculate checksum to check if the segment is error free
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr1[76];
		sum=0;
		checksum=0;
		wrap=0;

		memcpy(checksum_arr1, TCP_segment, 152); //Copying 24+128 bytes

		for (int i=0;i<76;i++)
		{
			//printf("0x%04X\n", checkksum_arr1[i]);
			sum = sum + checksum_arr1[i];
		}

		wrap = sum >> 16;// Wrap around once  
		sum = sum & 0x0000FFFF;   
		sum = wrap + sum;  
		wrap = sum >> 16;// Wrap around once more  
		sum = sum & 0x0000FFFF;  
		checksum = wrap + sum;  
		//printf("\nSum Value: 0x%04X\n", checksum);  /* XOR the sum for checksum */  
		//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^checksum));
	
		error_check = false;
		TCP_segment->checksum = temp_checksum;
		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				error_check = true;
				//Print values
				printf("TCP source port: %d\n", TCP_segment->srcport);
				printf("TCP destination port: %d\n", TCP_segment->destport);
				printf("TCP sequence number: %d\n", TCP_segment->seqnum);
				printf("TCP ack number: %d\n", TCP_segment->acknum);
				printf("TCP offset/ header length: %d\n", TCP_segment->offset);
				printf("TCP URG bit value: %d\n", TCP_segment->urg);
				printf("TCP ACK bit value: %d\n", TCP_segment->ack);
				printf("TCP PSH bit value: %d\n", TCP_segment->psh);
				printf("TCP RST bit value: %d\n", TCP_segment->rst);
				printf("TCP SYN bit value: %d\n", TCP_segment->syn);
				printf("TCP FIN bit value: %d\n", TCP_segment->fin);
				printf("TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
				printf("Checksum check: good. Bits check: good\n");
	
				fprintf(fp, "\nClient received ACK signal from server\n");
				fprintf(fp, "TCP source port: %d\n", TCP_segment->srcport);
				fprintf(fp, "TCP destination port: %d\n", TCP_segment->destport);
				fprintf(fp, "TCP sequence number: %d\n", TCP_segment->seqnum);
				fprintf(fp, "TCP ack number: %d\n", TCP_segment->acknum);
				fprintf(fp, "TCP offset/ header length: %d\n", TCP_segment->offset);
				fprintf(fp, "TCP URG bit value: %d\n", TCP_segment->urg);
				fprintf(fp, "TCP ACK bit value: %d\n", TCP_segment->ack);
				fprintf(fp, "TCP PSH bit value: %d\n", TCP_segment->psh);
				fprintf(fp, "TCP RST bit value: %d\n", TCP_segment->rst);
				fprintf(fp, "TCP SYN bit value: %d\n", TCP_segment->syn);
				fprintf(fp, "TCP FIN bit value: %d\n", TCP_segment->fin);
				fprintf(fp, "TCP check sum in decimal: %d and hexadecimal: %x\n", TCP_segment->checksum, TCP_segment->checksum);
			}
			else
			{
				printf("Error: ACK bit from TCP segment is incorrect\n");
			}		
		}
		else
		{
			printf("Error! Checksum of TCP segment are incorrect\n");
		}
	}

	if(error_check)
	{
		printf("\n---------------------------------------------------\n");
		client_close_TCP_connection(socket_fd, TCP_segment);
	}

	fclose(fp);
	//free(TCP_segment);
}


int main(int argc, char *argv[])
{
	FILE *fp;
	if (argc == 3)
	{
		portnum = atoi(argv[1]);
		fp = fopen(argv[2],"r");
		if(fp == NULL)
		{
			printf("Error! Cannot open file %s\n", argv[2]);   
			exit(1);             
		}
	}
	else
	{
		printf("Please enter port number of server and file name\n");
		exit(0);
	}

	int length;
	int socket_fd;
	struct sockaddr_in server_addr;
	socket_fd = socket(AF_INET, SOCK_STREAM,0);
	server_addr.sin_port = htons(portnum);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("129.120.151.94");
	
	int sk_option = 1;
	//display if failed to send
	if(setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &sk_option, sizeof(sk_option)) < 0 ) 
	{ 
		perror("ERROR: setsockopt failed"); 
		return EXIT_FAILURE; 
	} 
  	
	//connect the server
	if ((connect (socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr))) == -1)
	{
		printf("Connection to socket failed \n");
		exit(EXIT_FAILURE);
	}

	char *buffer = malloc (sizeof(char)* 1025);
	size_t buffer_length;

	if (fp != NULL)
	{
		buffer_length = fread(buffer, sizeof(char), 1024, fp);
		if (ferror(fp) != 0)
		{
			printf("Error reading file\n");
		}
		else
		{
			buffer[buffer_length+1] = '\0';
		}
	}
	fclose(fp);

	//printf("%s\n", buffer);

	client_three_way_handshake(socket_fd, buffer, buffer_length);
	printf("\n---------------------------------------------------\n");
	
	free(buffer);
	return 0;
}