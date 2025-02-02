/*
 * This file is part of networking-tools.
 *
 * networking-tools is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * networking-tools is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with networking-tools.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "otherFunctions.h"

int sendString(int sockfd, const unsigned char *buffer, int bytesToSend)
{
	int sentBytes;

	while(bytesToSend > 0)
	{
		sentBytes = send(sockfd, buffer, bytesToSend, 0);

		// return 0 on error
		if(sentBytes == -1)
			return 0;

		bytesToSend -= sentBytes;
		buffer += sentBytes;
	}

	return 1;
}

int recvLine(int sockfd, unsigned char *destBuffer)
{
#define EOL "\r\n"
#define EOL_SIZE 2

	unsigned char *ptr;
	int eolMatched = 0;

	ptr = destBuffer;

	while(recv(sockfd, ptr, 1, 0) == 1)
	{
		if(*ptr == EOL[eolMatched])
		{
			eolMatched++;

			if(eolMatched == EOL_SIZE)
			{
				*(ptr - EOL_SIZE + 1) = '\0';
				return strlen((char *)destBuffer);
			}
		}

		else
			eolMatched = 0;

		ptr++;
	}

	// no end of line character found
	return 0;
}

void dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr)
{
	unsigned int printLocation = 0;
	char byte;

	while(printLocation < length)
	{
		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i < length)
				fprintf(outputFilePtr, "%02x ", dataBuffer[printLocation + i]);

			else
				fprintf(outputFilePtr, "   ");
		}

		fprintf(outputFilePtr, " | ");

		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i < length)
			{
				byte = dataBuffer[printLocation + i];

				if(byte > 31 && byte < 127)
					fprintf(outputFilePtr, "%c ", byte);

				else
					fprintf(outputFilePtr, ", ");
			}

			else
			{
				fprintf(outputFilePtr, "\n");
				break;
			}
		}

		fprintf(outputFilePtr, "\n");
		printLocation += 16;
	}
}

void pretty_dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr, const char *prefix, const char *postfix)
{
	unsigned int printLocation = 0;
	char byte;

	while(printLocation < length)
	{
		fprintf(outputFilePtr, "%s", prefix);

		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i < length)
				fprintf(outputFilePtr, "%02x ", dataBuffer[printLocation + i]);

			else
				fprintf(outputFilePtr, "   ");
		}

		fprintf(outputFilePtr, " | ");

		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i < length)
			{
				byte = dataBuffer[printLocation + i];

				if(byte > 31 && byte < 127)
					fprintf(outputFilePtr, "%c ", byte);

				else
					fprintf(outputFilePtr, ", ");
			}

			else
				fprintf(outputFilePtr, "   ");
		}

		fprintf(outputFilePtr, "%s", postfix);
		fprintf(outputFilePtr, "\n");
		printLocation += 16;
	}
}

void hex_stream_dump(const unsigned char *databuffer, const unsigned int length, FILE *outputFilePtr)
{
	unsigned int printLocation = 0;

	while(printLocation < length)
	{
		fprintf(outputFilePtr, "%02x ", databuffer[printLocation]);
		printLocation++;
	}

	fprintf(outputFilePtr, "\n");
}

void free_all_pointers(struct allocated_pointers *head)
{
	struct allocated_pointers *next = NULL;
	struct allocated_pointers *prev = NULL;
	next = head->next_pointer;
	prev = head;

	while(next != NULL)
	{
		free(prev);
		free(next->pointer);
		prev = next;
		next = next->next_pointer;
	}

	free(prev);
}

void add_new_pointer(struct allocated_pointers *head, struct allocated_pointers **tail, void *new_pointer)
{
	struct allocated_pointers *new_node = (struct allocated_pointers *)malloc(sizeof(struct allocated_pointers));

	if(new_node == NULL)
	{
		free_all_pointers(head);
		fatal("allocating memory for a new node", "add_new_pointer", NULL);
	}

	new_node->pointer = new_pointer;
	new_node->next_pointer = NULL;

	struct allocated_pointers *tail_pointer;

	// find tail automatically if tail is NULL
	if(tail == NULL)
	{
		tail_pointer = head;

		while(tail_pointer->next_pointer != NULL)
			tail_pointer = tail_pointer->next_pointer;
	}

	else
		tail_pointer = *tail;

	tail_pointer->next_pointer = new_node;

	if(tail != NULL)
		*tail = new_node;
}

void remove_from_list(struct allocated_pointers **head, struct allocated_pointers **tail, void *remove_this)
{
	struct allocated_pointers *current;
	struct allocated_pointers *previous;

	current = *head;
	previous = NULL;

	if(current == remove_this)
	{
		*head = current->next_pointer;

		if(*head == NULL)
			*tail = NULL;

		free(current);
		return;
	}

	while(current != remove_this)
	{
		previous = current;
		current = current->next_pointer;

		if(current == NULL)
			fatal("pointer to free not found in allocated pointer list", "free_pointer", NULL);
	}

	previous->next_pointer = current->next_pointer;
	free(current);

	if(previous->next_pointer == NULL)
		*tail = previous;

	return;
}

void remove_all_from_list(struct allocated_pointers *head)
{
	struct allocated_pointers *current;
	struct allocated_pointers *previous;

	current = head;

	if(current->next_pointer == NULL)
	{
		free(current);
		return;
	}

	while(current != NULL)
	{
		previous = current;
		current = current->next_pointer;
		free(previous);
	}
}

void fatal(const char *message, const char *location, FILE *outputFilePtr)
{
	char error_message[ERROR_MESSAGE_SIZE];
	int lengthLeft = ERROR_MESSAGE_SIZE;

	strcpy(error_message, "[!!] Fatal Error ");
	lengthLeft -= 17;
	strncat(error_message, message, lengthLeft);
	lengthLeft -= strlen(message);
	strncat(error_message, "\nIn function: ", lengthLeft);
	lengthLeft -= 14;
	strncat(error_message, location, lengthLeft);
	lengthLeft -= strlen(location);

	if(outputFilePtr != NULL)
		fprintf(outputFilePtr, "%s\nerrno: %d", error_message, errno);

	exit(-1);
}

void bulk_print(const struct FILE_POINTERS files, int argCount, ...)
{
#define MAX_STRING_LENGTH 30
	va_list args;
	va_start(args, argCount);
	char string[MAX_STRING_LENGTH];

	for(int j = 0; j < argCount; j++)
	{
		strcpy(string, va_arg(args, char *));

		for(int i = 0; i < files.count; i++)
			fprintf(files.pointers[i], "%s", string);
	}

	va_end(args);
}

void itoa(const int number, char *destination)
{
	if(number == 0)
	{
		destination[0] = '0';
		destination[1] = '\0';
		return;
	}

	int digitCount = floor(log(number) / log(10)) + 1;

	for(int i = 0; i < digitCount; i++)
		destination[i] = (number / ((int)pow(10, digitCount - 1 - i)) % 10) + '0';

	destination[digitCount] = '\0';
}

int hex_stream_to_bytes(char *fileName, unsigned char **packet)
{
	FILE *inputFilePtr = fopen(fileName, "r");

	if(inputFilePtr == NULL)
		fatal("converting hex stream to bytes", "hex_stream_to_bytes", NULL);

	char hex_stream[HEX_STREAM_LENGTH];
	int stream_length = fread(hex_stream, 1, HEX_STREAM_LENGTH, inputFilePtr);
	fclose(inputFilePtr);

	hex_stream[stream_length - 1] = '\0';
	stream_length--;

	if(stream_length % 2 != 0)
		fatal("stream length not even", "hex_stream_to_bytes", NULL);

	char byte[3];
	byte[2] = '\0';
	unsigned char *bytes = (unsigned char *)malloc(stream_length / 2);

	if(bytes == NULL)
		fatal("allocating space for bytes", "hex_stream_to_bytes", NULL);

	for(int i = 0; i < stream_length; i += 2)
	{
		byte[0] = hex_stream[i];
		byte[1] = hex_stream[i + 1];
		bytes[i / 2] = (unsigned char)strtol(byte, NULL, 16);
	}

	*packet = bytes;

	return stream_length / 2;
}

pthread_mutex_t *setupMutexes(int mutexCount)
{
	char functionName[] = "setupMutexes";
	pthread_mutex_t *mutexList = NULL;
	mutexList = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t) * mutexCount);

	if(mutexList == NULL)
		fatal("creating mutexes", functionName, stdout);

	for(int i = 0; i < mutexCount; i++)
	{
		if(pthread_mutex_init(&mutexList[i], NULL) != 0)
			fatal("initializing mutexes", functionName, stdout);
	}

	return mutexList;
}

void cleanMutexes(pthread_mutex_t *mutexes, int mutexCount)
{
	for(int i = 0; i < mutexCount; i++)
	{
		if(pthread_mutex_destroy(&mutexes[i]) != 0)
			fatal("destroying mutexes", "cleanMutexes", stdout);
	}

	free(mutexes);
}

void gzipCompress(const char *inputFileName)
{
#define CHUNK 16384
	FILE* source = fopen(inputFileName, "rb");
	if(source == NULL)
		fatal("opening source file", "gzipCompress", stdout);
	
	char outputFileName[100];
	strcpy(outputFileName, inputFileName);
	strcat(outputFileName, ".gz");
	gzFile destination = gzopen(outputFileName, "wb");
	if(destination == NULL)
		fatal("opening destination file", "gzipCompress", stdout);
	
	unsigned char buffer[CHUNK];
	int bytes_read = 0;
	while((bytes_read = fread(buffer, 1, CHUNK, source))>0)
	{
		if(gzwrite(destination, buffer, bytes_read) != bytes_read)
			fatal("writing data", "gzipCompress", stdout);
	}

	fclose(source);
	gzclose(destination);
}

bool isNumber(const char *stringToCheck)
{
	int stringLength = strlen(stringToCheck);

	for(int i = 0; i < stringLength; i++)
	{
		if(stringToCheck[i] >= 48 && stringToCheck[i] <= 57)
			continue;

		else
			return false;
	}

	return true;
}
