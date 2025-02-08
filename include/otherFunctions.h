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

#pragma once
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <zlib.h>

#define HEX_STREAM_LENGTH 500
#define MAX_FILE_POINTERS_NUMBER 5

#ifndef ERROR_MESSAGE_SIZE
#define ERROR_MESSAGE_SIZE 200
#endif

extern volatile sig_atomic_t exit_flag;
extern char error_message[ERROR_MESSAGE_SIZE];

// linked list of allocated pointers for easy deallocation
struct allocated_pointers
{
	void *pointer;
	struct allocated_pointers *next_pointer;
};

// to easily print to multiple files
struct file_pointers
{
	int count;
	FILE *pointers[MAX_FILE_POINTERS_NUMBER];
};

// socket functions
int sendString(int sockfd, const unsigned char *buffer, int bytes_to_send);
int recvLine(int sockfd, unsigned char *destination_buffer);

// dump
void dump(const unsigned char *data_buffer, const unsigned int length, FILE *output_file_ptr);
void formattedDump(const unsigned char *data_buffer, const unsigned int length,
				   FILE *output_file_ptr, const char *prefix, const char *postfix);
void hexStreamDump(const unsigned char *data_buffer, const unsigned int length,
				   FILE *output_file_ptr);

// pointer functions
void freeAllPointers(struct allocated_pointers *head);
void addNewPointer(struct allocated_pointers *head, struct allocated_pointers **tail,
				   void *new_pointer);
void removeFromList(struct allocated_pointers **head, struct allocated_pointers **tail,
					void *remove_this);
void removeAllFromList(struct allocated_pointers *head);

// etc
void fatal(const char *message, const char *location, FILE *output_file_ptr);
void bulkPrint(const struct file_pointers files, int arg_count, ...);
void itoa(const int number, char *destination);
void gzipCompress(const char *input_file_name);
bool isNumber(const char *string_to_check);

// signal functions
void setExitFlag(int sig);
bool exitFlagSet();
int SIGINTSetsExitFlag();
int SIGINTDefault();

// debugging functions
int hexStreamToBytes(char *file_name, unsigned char **packet);

// mutex functions
pthread_mutex_t *setupMutexes(int mutex_count);
void cleanMutexes(pthread_mutex_t *mutexes, int mutex_count);
