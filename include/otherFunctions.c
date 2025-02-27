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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "otherFunctions.h"

volatile sig_atomic_t exit_flag = 0;
char error_message[ERROR_MESSAGE_SIZE];

int sendString(int sockfd, const unsigned char *buffer, int bytes_to_send)
{
	int sent_bytes;

	while(bytes_to_send > 0)
	{
		sent_bytes = send(sockfd, buffer, bytes_to_send, 0);

		// return 0 on error
		if(sent_bytes == -1)
			return 0;

		bytes_to_send -= sent_bytes;
		buffer += sent_bytes;
	}

	return 1;
}

int recvLine(int sockfd, unsigned char *destination_buffer)
{
#define EOL "\r\n"
#define EOL_SIZE 2

	unsigned char *ptr;
	int eol_matched = 0;

	ptr = destination_buffer;

	while(recv(sockfd, ptr, 1, 0) == 1)
	{
		if(*ptr == EOL[eol_matched])
		{
			eol_matched++;

			if(eol_matched == EOL_SIZE)
			{
				*(ptr - EOL_SIZE + 1) = '\0';
				return strlen((char *)destination_buffer);
			}
		}

		else
			eol_matched = 0;

		ptr++;
	}

	// no end of line character found
	return 0;
}

void dump(const unsigned char *data_buffer, const unsigned int length, FILE *output_file_ptr)
{
	unsigned int print_location = 0;
	char byte;

	while(print_location < length)
	{
		for(int i = 0; i < 16; i++)
		{
			if(print_location + i < length)
				fprintf(output_file_ptr, "%02x ", data_buffer[print_location + i]);

			else
				fprintf(output_file_ptr, "   ");
		}

		fprintf(output_file_ptr, " | ");

		for(int i = 0; i < 16; i++)
		{
			if(print_location + i < length)
			{
				byte = data_buffer[print_location + i];

				if(byte > 31 && byte < 127)
					fprintf(output_file_ptr, "%c ", byte);

				else
					fprintf(output_file_ptr, ", ");
			}

			else
			{
				fprintf(output_file_ptr, "\n");
				break;
			}
		}

		fprintf(output_file_ptr, "\n");
		print_location += 16;
	}
}

void formattedDump(const unsigned char *data_buffer, const unsigned int length,
				   FILE *output_file_ptr, const char *prefix, const char *postfix)
{
	unsigned int print_location = 0;
	char byte;

	while(print_location < length)
	{
		fprintf(output_file_ptr, "%s", prefix);

		for(int i = 0; i < 16; i++)
		{
			if(print_location + i < length)
				fprintf(output_file_ptr, "%02x ", data_buffer[print_location + i]);

			else
				fprintf(output_file_ptr, "   ");
		}

		fprintf(output_file_ptr, " | ");

		for(int i = 0; i < 16; i++)
		{
			if(print_location + i < length)
			{
				byte = data_buffer[print_location + i];

				if(byte > 31 && byte < 127)
					fprintf(output_file_ptr, "%c ", byte);

				else
					fprintf(output_file_ptr, ", ");
			}

			else
				fprintf(output_file_ptr, "   ");
		}

		fprintf(output_file_ptr, "%s", postfix);
		fprintf(output_file_ptr, "\n");
		print_location += 16;
	}
}

void hexStreamDump(const unsigned char *data_buffer, const unsigned int length,
				   FILE *output_file_ptr)
{
	unsigned int print_location = 0;

	while(print_location < length)
	{
		fprintf(output_file_ptr, "%02x ", data_buffer[print_location]);
		print_location++;
	}

	fprintf(output_file_ptr, "\n");
}

void freeAllPointers(struct allocated_pointers *head)
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

void addNewPointer(struct allocated_pointers *head, struct allocated_pointers **tail,
				   void *new_pointer)
{
	struct allocated_pointers *new_node =
		(struct allocated_pointers *)malloc(sizeof(struct allocated_pointers));

	if(new_node == NULL)
	{
		freeAllPointers(head);
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

void removeFromList(struct allocated_pointers **head, struct allocated_pointers **tail,
					void *remove_this)
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

void removeAllFromList(struct allocated_pointers *head)
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

void fatal(const char *message, const char *location, FILE *output_file_ptr)
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

	if(output_file_ptr != NULL)
		fprintf(output_file_ptr, "%s\nerrno: %d", error_message, errno);

	exit(-1);
}

void bulkPrint(const struct file_pointers files, int arg_count, ...)
{
#define MAX_STRING_LENGTH 30
	va_list args;
	va_start(args, arg_count);
	char string[MAX_STRING_LENGTH];

	for(int j = 0; j < arg_count; j++)
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

	int digit_count = floor(log(number) / log(10)) + 1;

	for(int i = 0; i < digit_count; i++)
		destination[i] = (number / ((int)pow(10, digit_count - 1 - i)) % 10) + '0';

	destination[digit_count] = '\0';
}

int hexStreamToBytes(char *file_name, unsigned char **packet)
{
	FILE *input_file_ptr = fopen(file_name, "r");

	if(input_file_ptr == NULL)
		fatal("converting hex stream to bytes", "hex_stream_to_bytes", NULL);

	char hex_stream[HEX_STREAM_LENGTH];
	int stream_length = fread(hex_stream, 1, HEX_STREAM_LENGTH, input_file_ptr);
	fclose(input_file_ptr);

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

pthread_mutex_t *setupMutexes(int mutex_count)
{
	char functionName[] = "setupMutexes";
	pthread_mutex_t *mutex_list = NULL;
	mutex_list = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t) * mutex_count);

	if(mutex_list == NULL)
		fatal("creating mutexes", functionName, stdout);

	for(int i = 0; i < mutex_count; i++)
	{
		if(pthread_mutex_init(&mutex_list[i], NULL) != 0)
			fatal("initializing mutexes", functionName, stdout);
	}

	return mutex_list;
}

void cleanMutexes(pthread_mutex_t *mutexes, int mutex_count)
{
	for(int i = 0; i < mutex_count; i++)
	{
		if(pthread_mutex_destroy(&mutexes[i]) != 0)
			fatal("destroying mutexes", "cleanMutexes", stdout);
	}

	free(mutexes);
}

void gzipCompress(const char *input_file_name)
{
#define CHUNK 16384
	FILE *source = fopen(input_file_name, "rb");
	if(source == NULL)
		fatal("opening source file", "gzipCompress", stdout);

	char output_file_name[100];
	strcpy(output_file_name, input_file_name);
	strcat(output_file_name, ".gz");
	gzFile destination = gzopen(output_file_name, "wb");
	if(destination == NULL)
		fatal("opening destination file", "gzipCompress", stdout);

	unsigned char buffer[CHUNK];
	int bytes_read = 0;
	while((bytes_read = fread(buffer, 1, CHUNK, source)) > 0)
	{
		if(gzwrite(destination, buffer, bytes_read) != bytes_read)
			fatal("writing data", "gzipCompress", stdout);
	}

	fclose(source);
	gzclose(destination);
}

bool isNumber(const char *string_to_check)
{
	int string_length = strlen(string_to_check);

	for(int i = 0; i < string_length; i++)
	{
		if(string_to_check[i] >= 48 && string_to_check[i] <= 57)
			continue;

		else
			return false;
	}

	return true;
}

void setExitFlag(int sig)
{
	printf("\n%d signal recieved. Setting exit_flag...\n", sig);
	exit_flag = 1;
}

bool exitFlagSet()
{
	if(exit_flag)
		return true;
	else
		return false;
}

int SIGINTSetsExitFlag()
{
	struct sigaction action;
	action.sa_handler = *setExitFlag;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	if(sigaction(SIGINT, &action, NULL) == -1)
	{
		perror("SIGINTSetsExitFlag");
		strcpy(error_message, "during sigaction");
		return -1;
	}

	return 0;
}

int SIGINTDefault()
{
	struct sigaction action;
	action.sa_handler = SIG_DFL;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	if(sigaction(SIGINT, &action, NULL) == -1)
	{
		perror("SIGINTDefault");
		strcpy(error_message, "during sigaction");
		return -1;
	}

	return 0;
}
