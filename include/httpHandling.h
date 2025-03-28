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

#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>

#define NAME_LENGTH 7
#define BUFFER_SIZE 4096
#define LISTENING_PORT "8080"
#define MAX_CONNECTION_COUNT 2
#define TIMEOUT_COUNT 20000
#define DOMAIN_NAME_LENGTH 6
#define DOMAIN_NAME_COUNT 7
#define RESPONSE_HEADER_COUNT 10
#define RESPONSE_NO_PAYLOAD 0x1

struct thread_parameters
{
	// connection info
	int *socket;
	int connection_ID;
	char connected_to[NAME_LENGTH];
	bool* shutdown;

	// read/write buffer info
	int* write_buffer_size;
	int* read_buffer_size;
	unsigned char* write_buffer;
	unsigned char* read_buffer;

	// file pointers
	FILE* output_file_ptr;
	FILE* debug_file_ptr;

	// mutex locks
	pthread_mutex_t *mutex_write_buffer;
	pthread_mutex_t *mutex_read_buffer;
};

struct listening_thread_parameters
{
	int listening_socket;
	int* accepted_socket;
	bool* accepted_socket_pending;
	bool* shutdown;
	// encloses both acceptedSocketPending and acceptedSocket
	pthread_mutex_t *mutex_accepted_socket;
};

struct connection_resources
{
	// connection info
	int client_socket;
	int server_socket;
	bool shutdown;
	
	// buffer info
	int data_from_client_size;
	int data_from_server_size;
	unsigned char data_from_client[BUFFER_SIZE+1];
	unsigned char data_from_server[BUFFER_SIZE+1];

	// mutex locks
	pthread_mutex_t mutex_data_from_client;
	pthread_mutex_t mutex_data_from_server;

	// thread info
	pthread_t serverThread;
	pthread_t clientThread;
	struct thread_parameters server_arguments;
	struct thread_parameters client_arguments;

	// file pointers
	FILE* output_file_ptr;
};

struct whitelist_structure
{
	char** IP_addresses;
	int IP_address_count;
	char** ports;
	int port_count;
	char** hostnames;
	int hostname_count;
};

struct header
{
	char* header_name;
	char* header_data;
};

struct HTTP_response
{
	char response_version[9];
	char status_code[7];
	struct header headers[];
};

// setup functions
void setDomainNames();
void setupConnectionResources(struct connection_resources* connections, int connection_count, FILE* global_output_file_ptr);
void setupWhitelist(struct whitelist_structure* whitelist);
void setupResponse(struct HTTP_response** destination, int options);

// action function
void handleHTTPConnection();
int sendResponse(int socket, const int options, const char* file_type, char* write_buffer, const struct HTTP_response* response, FILE* output_file_ptr);

// return sockets
int returnListeningSocket();
int returnSocketToClient(const int listening_socket);
int returnSocketToServer(const struct addrinfo destination_address_information);

// get information
int getDestinationName(const unsigned char* received_data, char* destination_name_buffer, FILE* output_file_ptr);
int getDestinationPort(const unsigned char* destination_name_end, char* destination_port_buffer, const bool is_HTTPS, FILE* output_file_ptr);
struct addrinfo returnDestinationAddressInfo(const char* destination_name, const char* destination_port, FILE* output_file_ptr);
int getHTTPRequestType(const char* received_data);
void getRequestedObject(const unsigned char *request_message, char *requested_object);

// verifying functions
bool isWhitelisted(const struct whitelist_structure whitelist, const char* destination_name, const char* destination_port, const struct addrinfo address_info);

// thread functions
void* whitelistedThreadFunction(void* args);
void* listeningThreadFunction(void* args);
void* blacklistedThreadFunction(void* args);

// clean up functions
void cleanupConnections(struct connection_resources *connection_resource, int connection_count);
