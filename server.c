/*Name: Yen Pham
CS3530
Project 4 - Simulate TCP 3-way handshake and closing a TCP connection in the application layer 
using a client-server architecture.
*/

#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h> 
#include <time.h> 
#include <math.h>
#include "TCP_segment.h"

int portnum;

void server_three_way_handshake(struct sockaddr_in client_addr, int socket_fd)
{
	bool error_check= false;
	//The server responds to the request by creating a connection granted TCP segment.
	struct tcp_seg *TCP_segment = malloc(sizeof(struct tcp_seg));
	int rec_bytes = recv(socket_fd, TCP_segment, 152, 0);
	//printf("Receive bytes: %d\n", rec_bytes);
	int header_length;
	FILE *fp;
	fp = fopen("server.out", "w"); //write mode
	unsigned short int temp_checksum;
	unsigned int sum, checksum, wrap;

	if (rec_bytes > 0)
	{
		printf("\nServer received SYN signal from client to create TCP connection\n");
		fprintf(fp,"\nServer received SYN signal from client to create TCP connection\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr[76];
		sum=0;
		checksum=0;
		wrap = 0;

		memcpy(checksum_arr, TCP_segment, 152); //Copying 24+128 = 152 bytes

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

		TCP_segment->checksum = temp_checksum;
		//printf("Checksum: %d\n", checksum);
		//printf("TCP_segment checksum: %d\n", TCP_segment->checksum);

		bool received_check = false;
		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->syn == 1)
			{
				received_check = true;
				//Print the values to console
				printf("No error founded. TCP segment is presented as below:\n");
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
				printf("Checksum check: good. Bits check: good \n");

				//Print values to file server.out
				fprintf(fp, "No error founded. TCP segment is presented as below:\n");
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
				fprintf(fp, "Checksum check: good. Bits check: good \n");
			}
			else
			{
				printf("Error: SYN bit does not equal to 1.\n");
			}
		}
		else
		{
			printf("Error: Checksum error. Cannot start TCP connection\n");
		}		

		if (received_check)
		{
			//Create a connection granted response
			TCP_segment->srcport = portnum;
			TCP_segment->destport = ntohs(client_addr.sin_port);
			srand(time(NULL));
			TCP_segment->acknum = TCP_segment->seqnum + 1; //Assign acknowledgement number equal to initial client sequence number + 1
			TCP_segment->seqnum = rand()% (int) (pow(2,32)); //Assign a random initial server sequence number
			header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
			TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
			TCP_segment->reserved = 0;
			TCP_segment->urg = 0;
			TCP_segment->ack = 1; //Set ACK bit to 1
			TCP_segment->psh = 0;
			TCP_segment->rst = 0;
			TCP_segment->syn = 1; //Set SYN bit to 1
			TCP_segment->fin = 0;
			TCP_segment->window = 0;
			TCP_segment->checksum = 0;
			TCP_segment->pointer = 0;
			TCP_segment->option = 0;
			memset(TCP_segment->data, 0, 128);

			//Calculate checksum
			unsigned short int checksum_arr1[76];
			sum=0;
			checksum=0;
			wrap = 0;
			memcpy(checksum_arr1, TCP_segment, 152); //Copying 24+128 = 152 bytes

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
			TCP_segment->checksum = checksum;

			int length = write(socket_fd, TCP_segment, 152);
			if (length < 0)
			{
				printf("Fail to send SYN ACK signal to client\n");
			}
			else
			{
				//Print the values to console
				printf("\nServer has sent SYN ACK signal to client succesfully\n");
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

				//Print values to file server.out
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
		}
	}

	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	//Once server receives ACK signal from client, TCP connection is created
	rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	if (rec_bytes > 0)
	{
		printf("\nServer received ACK signal from client.\n");
		fprintf(fp, "\nServer received ACK signal from client.\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr2[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr2, TCP_segment, 152); //Copying 24 + 128 data bytes = 152

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
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				error_check = true;
				//Print the values to console
				printf("\nTCP connection is now created\n");
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
				printf("Data chunk received from the client: %s\n", TCP_segment->data);

				fprintf(fp, "\nTCP connection is now created\n");
				//Print values to file server.out
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
				fprintf(fp, "Data chunk received from the client (128 bytes): %s\n", TCP_segment->data);
			}
			else
			{
				printf("Error: ACK bit is incorrect\n");
			}	
		}
		else
		{
			printf("Error: Checksum is incorrect\n");
		}	
	}

	FILE *fp1;
	unsigned int temp_seqnum;
	if (error_check)
	{
		//The server checks the data section and stores or appends the data into a text file
		fp1 = fopen("server_text_file.txt", "w");
		fprintf(fp1, "%s", TCP_segment->data);
		
		//The server then responds back with an ACK segment
		TCP_segment->srcport = portnum;
		TCP_segment->destport = ntohs(client_addr.sin_port);
		srand(time(NULL));
		temp_seqnum = TCP_segment->seqnum;
		TCP_segment->seqnum = TCP_segment->acknum; //sequence number equal to the received acknowledgement number from the client
		TCP_segment->acknum = temp_seqnum + 128; //acknowledgement number equal to the next starting byte that is needed from client
		header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
		TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
		TCP_segment->reserved = 0;
		TCP_segment->urg = 0;
		TCP_segment->ack = 1; //Set ACK bit to 1
		TCP_segment->psh = 0;
		TCP_segment->rst = 0;
		TCP_segment->syn = 0;
		TCP_segment->fin = 0;
		TCP_segment->window = 0;
		TCP_segment->checksum = 0;
		TCP_segment->pointer = 0;
		TCP_segment->option = 0;
		
		//Calculate checksum
		unsigned short int checksum_arr3[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr3, TCP_segment, 152); //Copying 24+128 = 152 bytes

		for (int i=0;i<76;i++)
		{
			//printf("0x%04X\n", checkksum_arr3[i]);
			sum = sum + checksum_arr3[i];
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

		int length = write(socket_fd, TCP_segment, 152);
		if (length < 0)
		{
			printf("Fail to send ACK signal to client\n");
		}
		else
		{
			//Print the values to console
			printf("\nServer has sent ACK signal to client succesfully\n");
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

			//Print values to file server.out
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
	}

	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	while (rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg)) > 0 && TCP_segment->reserved != 1)
	{
		error_check = false;
		printf("\nServer received ACK signal from client.\n");
		fprintf(fp, "\nServer received ACK signal from client.\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr2[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr2, TCP_segment, 152); //Copying 24 + 128 data bytes = 152

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
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				error_check = true;
				//Print the values to console
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
				printf("Data chunk received from the client: %s\n", TCP_segment->data);

				fprintf(fp, "\nTCP connection is now created\n");
				//Print values to file server.out
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
				fprintf(fp, "Data chunk received from the client (128 bytes): %s\n", TCP_segment->data);
			}
			else
			{
				printf("Error: ACK bit is incorrect\n");
			}	
		}
		else
		{
			printf("Error: Checksum is incorrect\n");
		}	

		if (error_check)
		{
			//The server checks the data section and stores or appends the data into a text file
			fprintf(fp1, "%s", TCP_segment->data);
		
			//The server then responds back with an ACK segment
			TCP_segment->srcport = portnum;
			TCP_segment->destport = ntohs(client_addr.sin_port);
			srand(time(NULL));
			temp_seqnum = TCP_segment->seqnum;
			TCP_segment->seqnum = TCP_segment->acknum; //sequence number equal to the received acknowledgement number from the client
			TCP_segment->acknum = temp_seqnum + 128; //acknowledgement number equal to the next starting byte that is needed from client
			header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
			TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
			TCP_segment->reserved = 0;
			TCP_segment->urg = 0;
			TCP_segment->ack = 1; //Set ACK bit to 1
			TCP_segment->psh = 0;
			TCP_segment->rst = 0;
			TCP_segment->syn = 0;
			TCP_segment->fin = 0;
			TCP_segment->window = 0;
			TCP_segment->checksum = 0;
			TCP_segment->pointer = 0;
			TCP_segment->option = 0;
			
			//Calculate checksum
			unsigned short int checksum_arr3[76];
			sum=0;
			checksum=0;
			wrap = 0;
			memcpy(checksum_arr3, TCP_segment, 152); //Copying 24+128 = 152 bytes
	
			for (int i=0;i<76;i++)
			{
				//printf("0x%04X\n", checkksum_arr3[i]);
				sum = sum + checksum_arr3[i];
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
	
			int length = write(socket_fd, TCP_segment, 152);
			if (length < 0)
			{
				printf("Fail to send ACK signal to client\n");
			}
			else
			{
				//Print the values to console
				printf("\nServer has sent ACK signal to client succesfully\n");
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
	
				//Print values to file server.out
				fprintf(fp, "\nServer has sent ACK signal to client succesfully\n");
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
				memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
			}
		}
	}

	if (TCP_segment->reserved == 1)
	{
		error_check = false;
		printf("\nServer received ACK signal from client.\n");
		fprintf(fp, "\nServer received ACK signal from client.\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr2[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr2, TCP_segment, 152); //Copying 24 + 128 data bytes = 152

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
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				error_check = true;
				//Print the values to console
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
				printf("Data chunk received from the client: %s\n", TCP_segment->data);

				fprintf(fp, "\nTCP connection is now created\n");
				//Print values to file server.out
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
				fprintf(fp, "Data chunk received from the client (128 bytes): %s\n", TCP_segment->data);
			}
			else
			{
				printf("Error: ACK bit is incorrect\n");
			}	
		}
		else
		{
			printf("Error: Checksum is incorrect\n");
		}	

		if (error_check)
		{
			//The server checks the data section and stores or appends the data into a text file
			fprintf(fp1, "%s", TCP_segment->data);

			//The server then responds back with an ACK segment
			TCP_segment->srcport = portnum;
			TCP_segment->destport = ntohs(client_addr.sin_port);
			srand(time(NULL));
			temp_seqnum = TCP_segment->seqnum;
			TCP_segment->seqnum = TCP_segment->acknum; //sequence number equal to the received acknowledgement number from the client
			TCP_segment->acknum = temp_seqnum + 128; //acknowledgement number equal to the next starting byte that is needed from client
			header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
			TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
			TCP_segment->reserved = 0;
			TCP_segment->urg = 0;
			TCP_segment->ack = 1; //Set ACK bit to 1
			TCP_segment->psh = 0;
			TCP_segment->rst = 0;
			TCP_segment->syn = 0;
			TCP_segment->fin = 0;
			TCP_segment->window = 0;
			TCP_segment->checksum = 0;
			TCP_segment->pointer = 0;
			TCP_segment->option = 0;
			
			//Calculate checksum
			unsigned short int checksum_arr3[76];
			sum=0;
			checksum=0;
			wrap = 0;
			memcpy(checksum_arr3, TCP_segment, 152); //Copying 24+128 = 152 bytes
	
			for (int i=0;i<76;i++)
			{
				//printf("0x%04X\n", checkksum_arr3[i]);
				sum = sum + checksum_arr3[i];
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
	
			int length = write(socket_fd, TCP_segment, 152);
			if (length < 0)
			{
				printf("Fail to send ACK signal to client\n");
			}
			else
			{
				//Print the values to console
				printf("\nServer has sent ACK signal to client succesfully\n");
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
	
				//Print values to file server.out
				fprintf(fp, "\nServer has sent ACK signal to client succesfully\n");
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
				memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
			}
		}
	}

	fclose(fp);
	free(TCP_segment);
}

void server_close_TCP_connection(struct sockaddr_in client_addr, int socket_fd)
{
	int length;
	int header_length;
	bool sent = false;
	bool error_check = false;
	unsigned short int temp_checksum;
	unsigned int temp_seqnum;
	unsigned int sum, checksum, wrap;

	//The server responds back with an acknowledgment TCP segment
	struct tcp_seg *TCP_segment = malloc(sizeof(struct tcp_seg)); //Create & allocate memory for an acknowledgement TCP segment
	int rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	FILE *fp;
	fp = fopen("server.out", "a"); // append mode

	if (rec_bytes > 0)
	{
		printf("\nServer received FIN signal from client to close TCP connection\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr, TCP_segment, 152); //Copying 24 + 128 data bytes = 152

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
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->fin == 1)
			{
				error_check = true;
				//Print the values to console
				printf("\nTCP connection is now created\n");
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
				printf("Data chunk received from the client: %s\n", TCP_segment->data);

				fprintf(fp, "\nTCP connection is now created\n");
				//Print values to file server.out
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
				fprintf(fp, "Data chunk received from the client (128 bytes): %s\n", TCP_segment->data);
			}
			else
			{
				printf("Error: ACK bit is incorrect\n");
			}	
		}
		else
		{
			printf("Error: Checksum is incorrect\n");
		}
	}	
	
	if (error_check)
	{
		TCP_segment->srcport = portnum;
		TCP_segment->destport = ntohs(client_addr.sin_port);
		temp_seqnum = TCP_segment->seqnum;
		TCP_segment->seqnum = TCP_segment->acknum; //Assign the server sequence number to the received acknowledgment number from the client
		TCP_segment->acknum = temp_seqnum+1; //acknowledgement number equal to client sequence number + 1
		header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
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
		unsigned int sum=0, checksum, wrap;

		memcpy(checksum_arr1, TCP_segment, 24); //Copying 24 bytes

		for (int i=0;i<12;i++)
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
		TCP_segment->checksum = checksum;

		length = write(socket_fd, TCP_segment, 24);
		if (length < 0)
		{
			printf("Fail to send ACK signal to client\n");
		}
		else
		{
			sent = true;
			//Print the values
			printf("\nACK signal has been sent to client succesfully\n");
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

			//Print values to file server.out
			fprintf(fp, "\nServer has sent ACK signal to client succesfully\n");
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

	if (sent)
	{
		//The server again sends another close acknowledgement TCP segment with FIN signal.
		temp_seqnum = TCP_segment->seqnum;
		unsigned int temp_acknum = TCP_segment->acknum;

		memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
		TCP_segment->srcport = portnum;
		TCP_segment->destport = ntohs(client_addr.sin_port);
		TCP_segment->seqnum = temp_seqnum; //Assign the server sequence number to the received acknowledgment number from the client
		TCP_segment->acknum = temp_acknum; //acknowledgement number equal to client sequence number + 1
		header_length = (16+16+32+32+4+6+6+16+16+16+32)/32;
		TCP_segment->offset = header_length; //24 bytes = 192 bits, 192/32=6
		TCP_segment->reserved = 0;
		TCP_segment->urg = 0;
		TCP_segment->ack = 0; //Set the ACK bit to 1
		TCP_segment->psh = 0;
		TCP_segment->rst = 0;
		TCP_segment->syn = 0;
		TCP_segment->fin = 1;
		TCP_segment->window = 0;
		TCP_segment->checksum = 0;
		TCP_segment->pointer = 0;
		TCP_segment->option = 0;
		memset(TCP_segment->data, 0, 128);

		//Calculate checksum
		unsigned short int checksum_arr2[12];
		unsigned int sum=0, checksum, wrap;

		memcpy(checksum_arr2, TCP_segment, 24); //Copying 24 bytes

		for (int i=0;i<12;i++)
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
		length = write(socket_fd, TCP_segment, 24);
		if (length < 0)
		{
			printf("Fail to send FIN signal to client\n");
		}
		else
		{
			//Print the values
			printf("\nFIN signal has been sent to client succesfully\n");
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

			//Print values to file server.out
			fprintf(fp, "\nServer has sent FIN signal to client succesfully\n");
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

	memset(TCP_segment, 0, sizeof(struct tcp_seg));	//reallocate memory
	rec_bytes = read(socket_fd, TCP_segment, sizeof(struct tcp_seg));
	if (rec_bytes > 0)
	{
		printf("\nServer received ACK signal from client.\n");

		//Calculate checksum
		temp_checksum = TCP_segment->checksum;
		TCP_segment->checksum = 0;
		unsigned short int checksum_arr[76];
		sum=0;
		checksum=0;
		wrap = 0;
		memcpy(checksum_arr, TCP_segment, 152); //Copying 24 + 128 data bytes = 152

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
		TCP_segment->checksum = temp_checksum;

		if (checksum == TCP_segment->checksum)
		{
			if (TCP_segment->ack == 1)
			{
				//Print the values to console
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
				printf("TCP connection is closed\nGood bye!\n");

				fprintf(fp, "\nServer received ACK signal from client.\n");
				//Print the values to file
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
				fprintf(fp, "TCP connection is closed\nGood bye!\n");
			}
			else
			{
				printf("Bit error. ACK bit is incorrect");
			}
		}
		else
		{
			printf("Checksum error! Segment is discarded.\n The client or server will not try to resend the segment if there is a loss or if the segment is in error.\n");
		}
	}
	fclose(fp);
	free(TCP_segment);
}

int main(int argc, char *argv[])
{
	int listen_fd, conn_fd;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	if (argc == 2)
	{
		portnum = atoi(argv[1]);
	}
	else
	{
		printf("Please enter port number of server\n");
		exit(0);
	}

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1)
	{
		perror("Cannot listen to socket\n");
		exit(EXIT_FAILURE);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(portnum);

	//to make sure it can use that some port later too
	int on = 1; 
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
	{
		perror("Bind error\n");
		exit(EXIT_FAILURE);
	}

	if (listen(listen_fd, 10) == -1)
	{
		perror("Listen error\n");
		exit(EXIT_FAILURE);
	}

	int length = sizeof(client_addr);
	conn_fd = accept (listen_fd, (struct sockaddr*) &client_addr, &length);

	printf("Server port: %d\n", portnum);
	printf("Client port: %d\n", ntohs(client_addr.sin_port));

	server_three_way_handshake(client_addr, conn_fd);
	printf("\n---------------------------------------------------\n");
	server_close_TCP_connection(client_addr, conn_fd);
	printf("\n---------------------------------------------------\n");

	return 0;
}