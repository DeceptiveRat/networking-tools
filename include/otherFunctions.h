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
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>
#include <zlib.h>
#include <stdbool.h>
#include <signal.h>

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
struct FILE_POINTERS
{
	int count;
	FILE* pointers[MAX_FILE_POINTERS_NUMBER];
};

// socket functions
int sendString(int sockfd, const unsigned char *buffer, int bytesToSend);
int recvLine(int sockfd, unsigned char *destBuffer);

// dump
void dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr);
void pretty_dump(const unsigned char *dataBuffer, const unsigned int length, FILE *outputFilePtr, const char *prefix, const char *postfix);
void hex_stream_dump(const unsigned char *databuffer, const unsigned int length, FILE *outputFilePtr);

// pointer functions
void free_all_pointers(struct allocated_pointers *head);
void add_new_pointer(struct allocated_pointers *head, struct allocated_pointers **tail, void *new_pointer);
void remove_from_list(struct allocated_pointers **head, struct allocated_pointers **tail, void *remove_this);
void remove_all_from_list(struct allocated_pointers *head);

// etc
void fatal(const char *message, const char *location, FILE *outputFilePtr);
void bulk_print(const struct FILE_POINTERS files, int argCount, ...);
void itoa(const int number, char* destination);
void gzipCompress(const char *inputFileName);
bool isNumber(const char* stringToCheck);

// signal functions
void setExitFlag(int sig);
bool exitFlagSet();
int SIGINTSetsExitFlag();
int SIGINTDefault();

// debugging functions
int hex_stream_to_bytes(char *fileName, unsigned char **packet);

// mutex functions
pthread_mutex_t* setupMutexes(int mutexCount);
void cleanMutexes(pthread_mutex_t* mutexes, int mutexCount);
