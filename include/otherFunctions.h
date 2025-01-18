#pragma once
#include <stdio.h>

#define ERROR_MESSAGE_SIZE 200
#define HEX_STREAM_LENGTH 500

// linked list of allocated pointers for easy deallocation
struct allocated_pointers
{
	void *pointer;
	struct allocated_pointers *next_pointer;
};

// socket functions
int sendString(int sockfd, const unsigned char *buffer, int bytesToSend);
int recvLine(int sockfd, unsigned char *destBuffer);

// dump
void dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr);
void pretty_dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr, const char *prefix, const char *postfix);
void hex_stream_dump(const unsigned char *databuffer, const unsigned int length, FILE *outputFilePtr);

// exit
void fatal(const char *message, const char *location, FILE *outputFilePtr);

// pointer functions
void free_all_pointers(struct allocated_pointers *head);
void add_new_pointer(struct allocated_pointers *head, struct allocated_pointers **tail, void *new_pointer);
void remove_from_list(struct allocated_pointers **head, struct allocated_pointers **tail, void *remove_this);
void remove_all_from_list(struct allocated_pointers *head);

// debugging functions
int hex_stream_to_bytes(char *fileName, unsigned char **packet);
