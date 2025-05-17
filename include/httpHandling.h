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

#include <ctype.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#define NAME_LENGTH 7
#define BUFFER_SIZE 4096
#define HTTP_LISTENING_PORT "8080"
#define HTTPS_LISTENING_PORT "8443"
#define MAX_CONNECTION_COUNT 1
#define TIMEOUT_COUNT 20000
#define DOMAIN_NAME_LENGTH 6
#define DOMAIN_NAME_COUNT 7
#define RESPONSE_HEADER_COUNT 10

struct thread_parameters
{
	// connection info
	int *socket;
	int connection_ID;
	char connected_to[NAME_LENGTH];
	bool *shutdown;
	bool *is_HTTPS;

	// read/write buffer info
	int *write_buffer_size;
	int *read_buffer_size;
	unsigned char *write_buffer;
	unsigned char *read_buffer;

	// file pointers
	FILE *output_file_ptr;
	FILE *debug_file_ptr;

	// mutex locks
	pthread_mutex_t *mutex_write_buffer;
	pthread_mutex_t *mutex_read_buffer;
};

struct listening_thread_parameters
{
	int listening_socket;
	int *accepted_socket;
	bool *accepted_socket_pending;
	bool *accepted_socket_HTTPS;
	bool *shutdown;
	bool is_HTTPS;
	// for both acceptedSocketPending and acceptedSocket
	pthread_mutex_t *mutex_accepted_socket;
};

struct connection_resources
{
	// connection info
	int client_socket;
	int server_socket;
	bool shutdown;
	bool is_HTTPS;

	// buffer info
	int data_from_client_size;
	int data_from_server_size;
	unsigned char data_from_client[BUFFER_SIZE + 1];
	unsigned char data_from_server[BUFFER_SIZE + 1];

	// mutex locks
	pthread_mutex_t mutex_data_from_client;
	pthread_mutex_t mutex_data_from_server;

	// thread info
	pthread_t serverThread;
	pthread_t clientThread;
	struct thread_parameters server_arguments;
	struct thread_parameters client_arguments;

	// file pointers
	FILE *output_file_ptr;
};

struct whitelist_structure
{
	char **IP_addresses;
	int IP_address_count;
	char **ports;
	int port_count;
	char **hostnames;
	int hostname_count;
};

struct header
{
	char *header_name;
	char *header_data;
};

struct HTTP_response
{
	char response_version[9];
	char status_code[7];
	struct header headers[];
};

// setup functions
void setDomainNames();
void setupConnectionResources(struct connection_resources *connections, int connection_count,
							  FILE *global_output_file_ptr);
void setupWhitelist(struct whitelist_structure *whitelist);
void setupResponse(struct HTTP_response **destination, int options);
void setupListeningFunctions(int *accepted_socket, bool *shutdown_listening_socket,
							 bool *accepted_socket_pending, bool *accepted_socket_HTTPS,
							 pthread_mutex_t *mutex_accepted_socket,
							 struct listening_thread_parameters *httpArgs,
							 struct listening_thread_parameters *httpsArgs);

// action function
void handleHTTPConnection();
#define RESPONSE_NO_PAYLOAD 0x1
#define RESPONSE_HTTPS 0x2
int sendResponse(int socket, const int options, const char *file_type, char *write_buffer,
				 const struct HTTP_response *response, FILE *output_file_ptr, SSL *ssl);
int responseToString(const struct HTTP_response *response, char *buffer);
int copyBuffer(unsigned char *read_buffer, int read_buffer_size, unsigned char *write_buffer,
			   int *write_buffer_size, pthread_mutex_t *mutex_write_buffer, FILE *output_file_ptr,
			   FILE *debug_file_ptr, int options, int connection_id, char *connected_to);
int sendAndClearBuffer(int socket, const unsigned char *read_buffer, int *read_buffer_size,
					   FILE *output_file_ptr, FILE *debug_file_ptr,
					   pthread_mutex_t *mutex_read_buffer, int connection_id, char *connected_to,
					   int options);
int receiveData(int socket, unsigned char *buffer, int buffer_size, int flags);
int parseAndRespond(const unsigned char *http_data, unsigned char *buffer, int socket,
					struct HTTP_response *http_response, int connection_id, int packet_count,
					FILE *output_file_ptr, FILE *debug_file_ptr, int sendResponse_options,
					SSL *ssl);

// return sockets
#define HTTP_LISTENER 0x1
#define HTTPS_LISTENER 0x2
int returnListeningSocket(int options);
int returnSocketToClient(const int listening_socket);
int returnSocketToServer(const struct addrinfo destination_address_information);

// get information
int getDestinationName(const unsigned char *received_data, char *destination_name_buffer,
					   FILE *output_file_ptr);
int getDestinationPort(const unsigned char *destination_name_end, char *destination_port_buffer,
					   const bool is_HTTPS, FILE *output_file_ptr);
struct addrinfo returnDestinationAddressInfo(const char *destination_name,
											 const char *destination_port, FILE *output_file_ptr);
int getHTTPRequestType(const char *received_data);
void getRequestedObject(const unsigned char *request_message, char *requested_object);

// verifying functions
bool isWhitelisted(const struct whitelist_structure whitelist, const char *destination_name,
				   const char *destination_port, const struct addrinfo address_info);

// thread functions
void *whitelistedThreadFunction(void *args);
void *listeningThreadFunction(void *args);
void *blacklistedThreadFunction(void *args);

// clean up functions
void cleanupConnections(struct connection_resources *connection_resource, int connection_count);
