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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

#include "httpHandling.h"
#include "otherFunctions.h"

pthread_mutex_t mutex_outputFile = PTHREAD_MUTEX_INITIALIZER;

char domainNames[DOMAIN_NAME_COUNT][DOMAIN_NAME_LENGTH];
void setDomainNames()
{
	FILE *domainNameFile = NULL;
	domainNameFile = fopen("domains.txt", "r");

	if(domainNameFile == NULL)
		fatal("opening file", "setDomainNames", stdout);

	for(int i = 0; i < DOMAIN_NAME_COUNT; i++)
		fscanf(domainNameFile, "%s", domainNames[i]);

	fclose(domainNameFile);
}

void setupConnectionResources(struct connection_resources* connections, int connection_count, FILE* global_output_file_ptr)
{
#define OUTPUT_FILE_NAME_LENGTH 40
#define OUTPUT_FILE_PATH "logs/"
	for(int i = 0; i < connection_count; i++)
	{
		// open output file
		FILE *output_file_ptr = 0;
		char file_name[OUTPUT_FILE_NAME_LENGTH];
		char file_path[] = OUTPUT_FILE_PATH;
		char connection_number[5];
		strcpy(file_name, file_path);
		strcat(file_name, "connection ");
		itoa(i + 1, connection_number);
		strcat(file_name, connection_number);
		strcat(file_name, " data exchange.log");
		output_file_ptr = fopen(file_name, "w");

		if(output_file_ptr == NULL)
			fatal("opening file", "setupConnectionResources", stdout);

		connections[i].shutdown = false;
		connections[i].output_file_ptr = output_file_ptr;

		// set up server arguments
		// connection info
		connections[i].server_arguments.socket = &connections[i].server_socket;
		connections[i].server_arguments.connection_ID = i;
		memcpy(connections[i].server_arguments.connected_to, "server\0", NAME_LENGTH);
		connections[i].server_arguments.shutdown = &connections[i].shutdown;
		// read/write buffer info
		connections[i].server_arguments.write_buffer_size = &connections[i].data_from_server_size;
		connections[i].server_arguments.read_buffer_size = &connections[i].data_from_client_size;
		connections[i].server_arguments.write_buffer = connections[i].data_from_server;
		connections[i].server_arguments.read_buffer = connections[i].data_from_client;
		// file pointers
		connections[i].server_arguments.output_file_ptr = output_file_ptr;
		connections[i].server_arguments.debug_file_ptr = global_output_file_ptr;
		// mutex locks
		connections[i].server_arguments.mutex_write_buffer = &connections[i].mutex_data_from_server;
		connections[i].server_arguments.mutex_read_buffer = &connections[i].mutex_data_from_client;

		// set up client arguments
		// connection info
		connections[i].client_arguments.socket = &connections[i].client_socket;
		connections[i].client_arguments.connection_ID = i;
		memcpy(connections[i].client_arguments.connected_to, "client\0", NAME_LENGTH);
		connections[i].client_arguments.shutdown = &connections[i].shutdown;
		// read/write buffer info
		connections[i].client_arguments.write_buffer_size = &connections[i].data_from_client_size;
		connections[i].client_arguments.read_buffer_size = &connections[i].data_from_server_size;
		connections[i].client_arguments.write_buffer = connections[i].data_from_client;
		connections[i].client_arguments.read_buffer = connections[i].data_from_server;
		// file pointers
		connections[i].client_arguments.output_file_ptr = output_file_ptr;
		connections[i].client_arguments.debug_file_ptr = global_output_file_ptr;

		// mutex locks
		connections[i].client_arguments.mutex_write_buffer = &connections[i].mutex_data_from_client;
		connections[i].client_arguments.mutex_read_buffer = &connections[i].mutex_data_from_server;
	}
}

void setupWhitelist(struct whitelist_structure *whitelist)
{
	const char function_name[] = "setupWhitelist";
	FILE *whitelist_file = fopen("whitelist.txt", "r");

	if(whitelist_file == NULL)
		fatal("reading whitelist file", "setupWhitelist", stdout);

	char string_read[100];
	int count = 0;

	// read ip addresses
	fgets(string_read, 100, whitelist_file);

	if(strcmp(string_read, "IP address\n") != 0)
		fatal("finding IP address start", function_name, stdout);

	fscanf(whitelist_file, "%s %d\n", string_read, &count);
	whitelist->IP_address_count = count;
	whitelist->IP_addresses = (char **)malloc(sizeof(char *)*count);

	if(whitelist->IP_addresses == NULL)
		fatal("allocating memory for IP addresses", function_name, stdout);

	for(int i = 0; i < count; i++)
	{
		int length;
		fscanf(whitelist_file, "%s\n", string_read);
		length = strlen(string_read);
		whitelist->IP_addresses[i] = (char*)malloc(sizeof(char)*length);
		strcpy(whitelist->IP_addresses[i], string_read);
	}

	// read ports
	fgets(string_read, 100, whitelist_file);
	if(strcmp(string_read, "Ports\n") != 0)
		fatal("finding ports start", function_name, stdout);
	
	fscanf(whitelist_file, "%s %d\n", string_read, &count);
	whitelist->port_count = count;
	whitelist->ports = (char **)malloc(sizeof(char *)*count);

	if(whitelist->ports == NULL)
		fatal("allocating memory for ports", function_name, stdout);

	for(int i = 0; i < count; i++)
	{
		int length;
		fscanf(whitelist_file, "%s\n", string_read);
		length = strlen(string_read);
		whitelist->ports[i] = (char*)malloc(sizeof(char)*length);
		strcpy(whitelist->ports[i], string_read);
	}

	// read hostnames
	fgets(string_read, 100, whitelist_file);
	if(strcmp(string_read, "Hostnames\n") != 0)
		fatal("finding hostnames start", function_name, stdout);
	
	fscanf(whitelist_file, "%s %d\n", string_read, &count);
	whitelist->hostname_count = count;
	whitelist->hostnames = (char **)malloc(sizeof(char *)*count);

	if(whitelist->hostnames == NULL)
		fatal("allocating memory for hostnames", function_name, stdout);

	for(int i = 0; i < count; i++)
	{
		int length;
		fscanf(whitelist_file, "%s\n", string_read);
		length = strlen(string_read);
		whitelist->hostnames[i] = (char*)malloc(sizeof(char)*length);
		strcpy(whitelist->hostnames[i], string_read);
	}

	fclose(whitelist_file);
}

void handleHTTPConnection()
{
#define DESTINATION_NAME_LENGTH 100
#define DESTINATION_PORT_LENGTH 5
	const char function_name[] = "handleHTTPConnection";
	setDomainNames();
	struct whitelist_structure whitelist;
	setupWhitelist(&whitelist);

	void* (*threadFunction)(void* args);

	FILE *output_file_ptr = 0;
	char path[OUTPUT_FILE_NAME_LENGTH];
	strcpy(path, OUTPUT_FILE_PATH);
	strcat(path, "connections.dbg");
	output_file_ptr = fopen(path, "w");

	if(output_file_ptr == NULL)
		fatal("opening file", function_name, stdout);

	// initialize local variables
	pthread_mutex_t *mutexes = setupMutexes(MAX_CONNECTION_COUNT * 2);
	struct connection_resources connections[MAX_CONNECTION_COUNT];

	for(int i = 0; i < MAX_CONNECTION_COUNT; i++)
	{
		connections[i].mutex_data_from_client = mutexes[i * 2];
		connections[i].mutex_data_from_server = mutexes[i * 2 + 1];
	}

	setupConnectionResources(connections, MAX_CONNECTION_COUNT, output_file_ptr);
	int connectionCount = 0;

	// initialize variables for listening thread
	pthread_t listeningThread;
	int hostSocket = returnListeningSocket();
	int accepted_socket;
	bool accepted_socket_pending;
	bool shutdownlistening_socket;
	pthread_mutex_t mutex_accepted_socket = PTHREAD_MUTEX_INITIALIZER;
	struct listening_thread_parameters listeningThreadArgs;

	listeningThreadArgs.listening_socket = hostSocket;
	listeningThreadArgs.accepted_socket = &accepted_socket;
	listeningThreadArgs.accepted_socket_pending = &accepted_socket_pending;
	listeningThreadArgs.shutdown = &shutdownlistening_socket;
	listeningThreadArgs.mutex_accepted_socket = &mutex_accepted_socket;

	// create listening thread
	pthread_create(&listeningThread, NULL, listeningThreadFunction, &listeningThreadArgs);

	while(!shutdownlistening_socket)
	{
		if(connectionCount == MAX_CONNECTION_COUNT)
			shutdownlistening_socket = true;

		// there is a new connection pending
		if(accepted_socket_pending && connectionCount < MAX_CONNECTION_COUNT)
		{
			struct connection_resources *temp = &connections[connectionCount];
			pthread_mutex_lock(&mutex_outputFile);
			printf("[   main   ] new connection made\n");
			fprintf(output_file_ptr, "[   main   ] new connection made\n");
			pthread_mutex_unlock(&mutex_outputFile);

			pthread_mutex_lock(&mutex_accepted_socket);
			temp->client_socket = accepted_socket;
			accepted_socket_pending = false;
			pthread_mutex_unlock(&mutex_accepted_socket);
			temp->data_from_client[0] = '\0';
			temp->data_from_server[0] = '\0';
			int receiveLength = recv(temp->client_socket, temp->data_from_client, BUFFER_SIZE, 0);

			if(receiveLength == -1)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
				{
					pthread_mutex_lock(&mutex_outputFile);
					printf("[   main   ] lost connection with %d:\n", connectionCount);
					fprintf(output_file_ptr, "[   main   ] lost connection with %d:\n", connectionCount);
					printf("[   main   ] resetting connection...\n");
					fprintf(output_file_ptr, "[   main   ] resetting connection...\n");
					pthread_mutex_unlock(&mutex_outputFile);
					close(temp->client_socket);
					continue;
				}

				// clean up code
				for(int i = 0; i < MAX_CONNECTION_COUNT; i++)
					connections[i].shutdown = true;

				//cleanupConnections(connections, connectionCount);
				pthread_mutex_destroy(&mutex_outputFile);
				fclose(output_file_ptr);
				cleanMutexes(mutexes, MAX_CONNECTION_COUNT * 2);
				fatal("receiving from client", function_name, stdout);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[   main   ] received %d bytes from client %d\n", receiveLength, connectionCount);
			fprintf(output_file_ptr, "[   main   ] received %d bytes from client %d\n", receiveLength, connectionCount);
			dump(temp->data_from_client, receiveLength, output_file_ptr);
			pthread_mutex_unlock(&mutex_outputFile);
			temp->data_from_client_size = receiveLength;

			// get information about server
			char destination_name[DESTINATION_NAME_LENGTH + 1];
			int functionResult = getDestinationName(temp->data_from_client, destination_name, output_file_ptr);

			if(functionResult == -1)
			{
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] error finding host string\n");
				fprintf(output_file_ptr, "[   main   ] error finding host string\n");
				pthread_mutex_unlock(&mutex_outputFile);
				close(temp->client_socket);
				continue;
			}

			char destinationPort[DESTINATION_PORT_LENGTH + 1] = LISTENING_PORT;

			struct addrinfo destinationAddressInformation = returnDestinationAddressInfo(destination_name, destinationPort, output_file_ptr);

			// not whitelisted
			if(!isWhitelisted(whitelist, destination_name, destinationPort, destinationAddressInformation))
			{
				temp->server_socket = 0;
				threadFunction = &blacklistedThreadFunction;
			}
			// whitelisted
			else
			{
				threadFunction = &whitelistedThreadFunction;

				// create socket to destination
				temp->server_socket = returnSocketToServer(destinationAddressInformation);
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] established TCP connection with server\n");
				fprintf(output_file_ptr, "[   main   ] established TCP connection with server\n");
				pthread_mutex_unlock(&mutex_outputFile);
			}

			// create threads
			pthread_create(&connections[connectionCount].clientThread, NULL, threadFunction, &connections[connectionCount].client_arguments);
			pthread_create(&connections[connectionCount].serverThread, NULL, threadFunction, &connections[connectionCount].server_arguments);

			connectionCount++;
		}
	}

	// wait for all connections to terminate
	for(int i = 0; i < connectionCount; i++)
	{
		pthread_join(connections[i].clientThread, NULL);
		pthread_join(connections[i].serverThread, NULL);
	}

	//cleanupConnections(connections, connectionCount);
	fclose(output_file_ptr);
	cleanMutexes(mutexes, MAX_CONNECTION_COUNT * 2);
	pthread_mutex_destroy(&mutex_outputFile);
}

bool isWhitelisted(const struct whitelist_structure whitelist, const char* destination_name, const char* destinationPort, const struct addrinfo addressInfo)
{
	char destinationAddressString[INET_ADDRSTRLEN];
	struct sockaddr_in destinationAddress_in = *(struct sockaddr_in *)addressInfo.ai_addr;

	if(inet_ntop(AF_INET, &destinationAddress_in.sin_addr, destinationAddressString, INET_ADDRSTRLEN) == NULL)
		fatal("converting destination ip address to string", "isWhitelisted", stdout);

	// test for IP address match
	for(int i = 0;i<whitelist.IP_address_count;i++)
	{
		if(strcmp(destinationAddressString, whitelist.IP_addresses[i]) == 0)
			return true;
	}

	// test for hostname match
	for(int i = 0;i<whitelist.hostname_count;i++)
	{
		if(strcmp(destination_name, whitelist.hostnames[i]) == 0)
			return true;
	}

	// test for port number match
	for(int i = 0;i<whitelist.port_count;i++)
	{
		if(strcmp(destinationPort, whitelist.ports[i]) == 0)
			return true;
	}

	// no match anywhere
	return false;
}

/* create, bind, and return a listening socket */
int returnListeningSocket()
{
	char function_name[] = "returnlistening_socket";
	struct addrinfo hostAddrHint, *hostResult;
	int hostSocket;

	memset(&hostAddrHint, 0, sizeof(struct addrinfo));
	hostAddrHint.ai_family = AF_INET;
	hostAddrHint.ai_socktype = SOCK_STREAM;
	hostAddrHint.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, LISTENING_PORT, &hostAddrHint, &hostResult);
	hostSocket = socket(hostResult->ai_family, hostResult->ai_socktype, hostResult->ai_protocol);

	if(hostSocket == -1)
		fatal("creating host socket", function_name, stdout);

	int yes = 1;

	if(setsockopt(hostSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
		fatal("setsockopt", function_name, stdout);

	if(bind(hostSocket, hostResult->ai_addr, hostResult->ai_addrlen) == -1)
		fatal("binding socket", function_name, stdout);

	if(listen(hostSocket, 10) == -1)
		fatal("listening on socket", function_name, stdout);

	freeaddrinfo(hostResult);
	return hostSocket;
}

/*
 * create, connect, and return a socket to the client
 */
int returnSocketToClient(const int listening_socket)
{
	struct sockaddr clientAddress;
	socklen_t sin_size = sizeof(struct sockaddr);
	int socketToClient;

	while(1)
	{
		socketToClient = accept(listening_socket, &clientAddress, &sin_size);

		if(socketToClient == -1)
		{
			printf("errno %d: ", errno);
			return -2;
		}

		// got connection
		else
			break;
	}

	char clientAddressString[INET_ADDRSTRLEN];
	struct sockaddr_in clientAddress_in = *((struct sockaddr_in *)&clientAddress);

	if(inet_ntop(AF_INET, &clientAddress_in.sin_addr, clientAddressString, INET_ADDRSTRLEN) != NULL)
		printf("got connection from %s port %d\n", clientAddressString, clientAddress_in.sin_port);

	return socketToClient;
}

/* extract the destination name string from the HTTP request */
/* returns offset of name from start of data, or on error:	-1 when error finding the host string */
int getDestinationName(const unsigned char *receivedData, char *destination_nameBuffer, FILE *output_file_ptr)
{
	char *destination_nameStart, *destination_nameEnd;
	int destination_nameLength;
	int domainNameIndex = 0;

	destination_nameStart = strstr((char *)receivedData, "Host: ");

	if(destination_nameStart == NULL)
		return -1;

	destination_nameStart += 6;
	destination_nameEnd = NULL;

	while(destination_nameEnd == NULL)
	{
		// reached end of file without finding domain
		if(domainNameIndex == DOMAIN_NAME_COUNT)
			return -1;

		destination_nameEnd = strstr(destination_nameStart, domainNames[domainNameIndex]);
		domainNameIndex++;
	}

	// TODO: change for domain names that aren't exactly 3 characters long
	destination_nameEnd += 4;
	destination_nameLength = destination_nameEnd - destination_nameStart;

	strncpy(destination_nameBuffer, destination_nameStart, destination_nameLength);
	destination_nameBuffer[destination_nameLength] = '\0';

	pthread_mutex_lock(&mutex_outputFile);
	printf("destination name is: %s\n", destination_nameBuffer);
	fprintf(output_file_ptr, "destination name is: %s\n", destination_nameBuffer);
	pthread_mutex_unlock(&mutex_outputFile);
	return (char *)receivedData - destination_nameStart;
}

/* get additional information about the destination */
struct addrinfo returnDestinationAddressInfo(const char *destination_name, const char *destinationPort, FILE *output_file_ptr)
{
	char function_name[] = "returnDestinationAddressInfo";
	struct addrinfo destinationAddressHint, *destinationAddressResult;
	memset(&destinationAddressHint, 0, sizeof(struct addrinfo));
	destinationAddressHint.ai_family = AF_INET;
	destinationAddressHint.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(destination_name, destinationPort, &destinationAddressHint, &destinationAddressResult) != 0)
		fatal("getting address information for the destination", function_name, stdout);

	char destinationAddressString[INET_ADDRSTRLEN];
	struct sockaddr_in destinationAddress_in = *(struct sockaddr_in *)destinationAddressResult->ai_addr;

	if(inet_ntop(AF_INET, &destinationAddress_in.sin_addr, destinationAddressString, INET_ADDRSTRLEN) == NULL)
		fatal("converting destination ip address to string", function_name, stdout);

	pthread_mutex_lock(&mutex_outputFile);
	printf("destination ip address: %s\n", destinationAddressString);
	fprintf(output_file_ptr, "destination ip address: %s\n", destinationAddressString);
	pthread_mutex_unlock(&mutex_outputFile);

	struct addrinfo destinationAddrInfo = *destinationAddressResult;
	freeaddrinfo(destinationAddressResult);

	return destinationAddrInfo;
}

/* create, connect, and return a socket to the server */
int returnSocketToServer(const struct addrinfo destinationAddressInformation)
{
	char function_name[] = "returnSocketToServer";
	int socketToDestination;
	socketToDestination = socket(destinationAddressInformation.ai_family, destinationAddressInformation.ai_socktype, destinationAddressInformation.ai_protocol);

	if(socketToDestination == -1)
		fatal("creating socket to server", function_name, stdout);

	if(connect(socketToDestination, destinationAddressInformation.ai_addr, destinationAddressInformation.ai_addrlen) == -1)
		fatal("connecting to server", function_name, stdout);

	return socketToDestination;
}

bool isConnectMethod(const unsigned char *receivedData)
{
	if(strstr((char *)receivedData, "CONNECT ") == NULL)
		return false;

	else
		return true;
}

void *whitelistedThreadFunction(void *args)
{
#define CONNECTION_TIMEOUT_VALUE 2
	// set up local variables with argument
	struct thread_parameters parameters = *(struct thread_parameters *)args;
	// connection info
	const int socket = *parameters.socket;
	const int ID = parameters.connection_ID;
	char connected_to[NAME_LENGTH];
	memcpy(connected_to, parameters.connected_to, NAME_LENGTH);
	bool *shutdown = parameters.shutdown;
	// read/write buffer info
	int *read_buffer_size = parameters.read_buffer_size;
	int *write_buffer_size = parameters.write_buffer_size;
	unsigned char *write_buffer = parameters.write_buffer;
	const unsigned char *read_buffer = parameters.read_buffer;
	// file pointers
	FILE *output_file_ptr = parameters.output_file_ptr;
	FILE *debug_file_ptr = parameters.debug_file_ptr;
	// mutex locks
	pthread_mutex_t *mutex_write_buffer = parameters.mutex_write_buffer;
	pthread_mutex_t *mutex_read_buffer = parameters.mutex_read_buffer;

	unsigned char tempread_buffer[BUFFER_SIZE + 1];
	ssize_t recvResult;

	// set up timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = CONNECTION_TIMEOUT_VALUE;
	setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
	int timeoutCount = 0;

	while(!(*shutdown))
	{
		// CONNECTION_TIMEOUT_VALUE seconds have passed idle
		if(timeoutCount >= TIMEOUT_COUNT)
		{
			*shutdown = true;
			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Terminating: idle connection\n", ID, connected_to);
			fprintf(debug_file_ptr, "[%d - %s] Terminating: idle connection\n", ID, connected_to);
			pthread_mutex_unlock(&mutex_outputFile);
			pthread_exit(NULL);
		}

		recvResult = recv(socket, tempread_buffer, BUFFER_SIZE, 0);

		// error reading data
		if(recvResult == -1)
		{
			if(errno != EAGAIN && errno != EWOULDBLOCK)
			{
				*shutdown = true;
				pthread_mutex_lock(&mutex_outputFile);
				printf("[%d - %s] Terminating: Error reading data.\nErrno: %d\n", ID, connected_to, errno);
				fprintf(debug_file_ptr, "[%d - %s] Terminating: Error reading data.\nErrno: %d\n", ID, connected_to, errno);
				pthread_mutex_unlock(&mutex_outputFile);
				pthread_exit(NULL);
			}

			// no data to read
			else
				timeoutCount++;
		}

		// data read
		else
		{
			timeoutCount = 0;

			if(recvResult == 0)
			{
				*shutdown = true;
				pthread_mutex_lock(&mutex_outputFile);
				printf("[%d - %s] Terminating: 0 bytes received\n", ID, connected_to);
				fprintf(debug_file_ptr, "[%d - %s] Terminating: 0 bytes received\n", ID, connected_to);
				pthread_mutex_unlock(&mutex_outputFile);
				pthread_exit(NULL);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Read %zd bytes\n", ID, connected_to, recvResult);
			fprintf(debug_file_ptr, "[%d - %s] Read %zd bytes\n", ID, connected_to, recvResult);
			fprintf(output_file_ptr, "[%d - %s] Read %zd bytes\n", ID, connected_to, recvResult);
			dump(tempread_buffer, recvResult, output_file_ptr);
			pthread_mutex_unlock(&mutex_outputFile);

			// wait until buffer is empty before writing to it
			while(*write_buffer_size != 0) {};

			// write to buffer and change buffer size
			pthread_mutex_lock(mutex_write_buffer);
			memcpy(write_buffer, tempread_buffer, recvResult);
			*write_buffer_size = recvResult;
			pthread_mutex_unlock(mutex_write_buffer);

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Wrote %zd bytes\n", ID, connected_to, recvResult);
			fprintf(debug_file_ptr, "[%d - %s] Wrote %zd bytes\n", ID, connected_to, recvResult);
			pthread_mutex_unlock(&mutex_outputFile);
		}

		// if there is data in the read buffer, send it
		if(*read_buffer_size != 0)
		{
			if(sendString(socket, read_buffer, *read_buffer_size) == 0)
			{
				pthread_mutex_lock(&mutex_outputFile);
				*shutdown = true;
				printf("[%d - %s] Terminating: error sending data\n", ID, connected_to);
				fprintf(debug_file_ptr, "[%d - %s] Terminating: error sending data\n", ID, connected_to);
				pthread_mutex_unlock(&mutex_outputFile);
				pthread_exit(NULL);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Sent data\n", ID, connected_to);
			fprintf(debug_file_ptr, "[%d - %s] Sent data\n", ID, connected_to);
			pthread_mutex_unlock(&mutex_outputFile);

			pthread_mutex_lock(mutex_read_buffer);
			*read_buffer_size = 0;
			pthread_mutex_unlock(mutex_read_buffer);

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Set buffer to empty\n", ID, connected_to);
			fprintf(debug_file_ptr, "[%d - %s] Set buffer to empty\n", ID, connected_to);
			pthread_mutex_unlock(&mutex_outputFile);
		}
	}

	// clean up code
	close(socket);
	pthread_mutex_lock(&mutex_outputFile);
	printf("[%d - %s] Terminating: shutdown variable set\n", ID, connected_to);
	fprintf(debug_file_ptr, "[%d - %s] Terminating: shutdown variable set\n", ID, connected_to);
	pthread_mutex_unlock(&mutex_outputFile);
	pthread_exit(NULL);
}

void *listeningThreadFunction(void *args)
{
	struct listening_thread_parameters parameter = *(struct listening_thread_parameters *)args;
	int listening_socket = parameter.listening_socket;
	int *accepted_socket = parameter.accepted_socket;
	bool *accepted_socket_pending = parameter.accepted_socket_pending;
	bool *shutdown = parameter.shutdown;
	pthread_mutex_t *mutex_accepted_socket = parameter.mutex_accepted_socket;

	int tempaccepted_socket = 0;

	printf("[ listener ] Listening on port %s\n", LISTENING_PORT);

	while(!(*shutdown))
	{
		if(tempaccepted_socket == 0)
			tempaccepted_socket = returnSocketToClient(listening_socket);

		if(tempaccepted_socket == -2)
		{
			printf("[ listener ] error while accepting connection\n");
			*shutdown = true;
			continue;
		}

		pthread_mutex_lock(mutex_accepted_socket);

		if(!(*accepted_socket_pending))
		{
			*accepted_socket = tempaccepted_socket;
			*accepted_socket_pending = true;
			tempaccepted_socket = 0;
		}

		pthread_mutex_unlock(mutex_accepted_socket);

	}

	if(tempaccepted_socket != 0)
		close(tempaccepted_socket);

	pthread_mutex_lock(mutex_accepted_socket);

	if(!(*accepted_socket_pending))
		close(*accepted_socket);

	pthread_mutex_unlock(mutex_accepted_socket);
	close(listening_socket);
	pthread_exit(NULL);
}

void cleanupConnections(struct connection_resources *conRes, int connectionCount)
{
	void *retval;
	int result;

	for(int i = 0; i < connectionCount; i++)
	{
		fclose(conRes[i].output_file_ptr);
		// TODO: add code to check for errors later
		result = pthread_tryjoin_np(conRes[i].clientThread, &retval);

		if(result == EBUSY)
			pthread_join(conRes[i].clientThread, NULL);

		result = pthread_tryjoin_np(conRes[i].serverThread, &retval);

		if(result == EBUSY)
			pthread_join(conRes[i].serverThread, NULL);
	}
}

void getRequestedObject(const unsigned char *requestMessage, char *requestedObject)
{
	char *requestedObjectEnd = strstr((char *)requestMessage, " HTTP/");

	if(requestedObjectEnd == NULL)
	{
		requestedObject[0] = '\0';
		return;
	}

	else
	{
		int nameLength = requestedObjectEnd - (char *)(requestMessage + 4);
		if((nameLength == 1) && (*(requestMessage + 4) == '/'))
			strcpy(requestedObject, "index.html\0");
		else
		{
			strncpy(requestedObject, (char *)(requestMessage + 4), nameLength);
			requestedObject[nameLength] = '\0';
		}
		return;
	}
}

int sendResponse(int socket, const int options, const char* fileType, char* write_buffer, const struct HTTP_response* response, FILE* output_file_ptr)
{
#define FILE_READ_BUFFER_SIZE 100
	memset(write_buffer, 0, 	BUFFER_SIZE);
	strcat(write_buffer, response->response_version);
	strcat(write_buffer, " ");
	strcat(write_buffer, response->status_code);
	strcat(write_buffer, "\r\n");
	for(int i = 0;i<RESPONSE_HEADER_COUNT;i++)
	{
		if(response->headers[i].header_name == NULL)
			break;
		else
		{
			strcat(write_buffer, response->headers[i].header_name);
			strcat(write_buffer, ": ");
			strcat(write_buffer, response->headers[i].header_data);
			strcat(write_buffer, "\r\n");
		}
	}
	strcat(write_buffer, "\r\n");
	int write_buffer_size = strlen(write_buffer);
	FILE* inputFile;
	if((options & RESPONSE_NO_PAYLOAD) == 0)
	{
		if(strcmp(fileType, "html") == 0)
		{
			gzipCompress("files/default.html");
			inputFile = fopen("files/default.html.gz", "rb");
			if(inputFile == NULL)
				return -2;
		}
		else
			return -1;

		char fileread_buffer[FILE_READ_BUFFER_SIZE];
		size_t bytesRead;
		while((bytesRead = fread(fileread_buffer, 1, FILE_READ_BUFFER_SIZE, inputFile)) > 0)
		{
			memcpy(write_buffer + write_buffer_size, fileread_buffer, bytesRead);
			write_buffer_size += bytesRead;
		}
	}

	fprintf(output_file_ptr, "Send response with size %d:\n", write_buffer_size);
	dump((unsigned char*)write_buffer, write_buffer_size, output_file_ptr);
	write(socket, write_buffer, write_buffer_size);
	fclose(inputFile);
	return 0;
}

void* blacklistedThreadFunction(void* args)
{
#define REQUESTED_OBJECT_NAME_LENGTH 30
#define REQUESTED_OBJECT_TYPE_LENGTH 7
	// set up local variables with argument
	struct thread_parameters parameters = *(struct thread_parameters *)args;
	const int socket = *parameters.socket;
	// terminate if server thread
	if(socket == 0)
		pthread_exit(NULL);
	const int ID = parameters.connection_ID;
	bool *shutdown = parameters.shutdown;
	// read/write buffer info
	unsigned char *data_from_client = parameters.write_buffer;
	unsigned char *dataToClient = parameters.read_buffer;
	// file pointers
	FILE *output_file_ptr = parameters.output_file_ptr;
	FILE *debug_file_ptr = parameters.debug_file_ptr;

	// local variables
	ssize_t recvResult;
	int requestType = 0;
	char requestedObject[REQUESTED_OBJECT_NAME_LENGTH];
	char requestedObjectType[REQUESTED_OBJECT_TYPE_LENGTH];
	static struct HTTP_response* defaultResponse = NULL;
	if(defaultResponse == NULL)
		setupResponse(&defaultResponse, 0);
	int packetCount = 0;

	while(!(*shutdown))
	{
		requestType = getHTTPRequestType((char*)data_from_client);
		if(requestType == 0)
		{
			fprintf(stdout, "[%d #%d] Packet not HTTP\n", ID, packetCount);
			fprintf(debug_file_ptr, "[%d #%d] Packet not HTTP\n", ID, packetCount);
			*shutdown = true;
			break;
		}

		getRequestedObject(data_from_client, requestedObject);
		strcpy(requestedObjectType, strstr(requestedObject, ".") + 1);

		switch(requestType)
		{
		case 1:
			int result;
			result = sendResponse(socket, 0, requestedObjectType, (char*)dataToClient, defaultResponse, output_file_ptr);
			if(result == -1)
			{
				fprintf(stdout, "[%d #%d] Unknown file type\n", ID, packetCount);
				fprintf(debug_file_ptr, "[%d #%d] Unknown file type\n", ID, packetCount);
				*shutdown = true;
				break;
			}
			else if(result == -2)
			{
				fprintf(stdout, "[%d #%d] Error opening file\n", ID, packetCount);
				fprintf(debug_file_ptr, "[%d #%d] Error opening file\n", ID, packetCount);
				*shutdown = true;
				break;
			}
			else
			{
				fprintf(stdout, "[%d #%d] Successfully sent response\n", ID, packetCount);
				fprintf(debug_file_ptr, "[%d #%d] Successfully sent response\n", ID, packetCount);
			}
			break;
		case 2:
			break;
		case 3:
			break;
		case 4:
			break;
		case 5:
			break;
		case 6:
			break;
		case 7:
			break;
		default:
			break;
		}

		recvResult = recv(socket, data_from_client, BUFFER_SIZE, 0);
		if(recvResult == -1)
		{
			fprintf(stdout, "[%d #%d] Error reading from socket\n", ID, packetCount);
			fprintf(debug_file_ptr, "[%d #%d] Error reading from socket\n", ID, packetCount);
			*shutdown = true;
			break;
		}
		fprintf(stdout, "[%d #%d] Received %zd byte packet\n", ID, packetCount, recvResult);
		fprintf(debug_file_ptr, "[%d #%d] Received %zd byte packet\n", ID, packetCount, recvResult);
		fprintf(output_file_ptr, "[%d #%d] Received %zd byte packet\n", ID, packetCount, recvResult);
		packetCount++;
		dump(data_from_client, recvResult, output_file_ptr);
	}

	// clean up code
	close(socket);
	pthread_mutex_lock(&mutex_outputFile);
	printf("[%d] Terminating: shutdown variable set\n", ID);
	fprintf(debug_file_ptr, "[%d] Terminating: shutdown variable set\n", ID);
	pthread_mutex_unlock(&mutex_outputFile);
	free(defaultResponse);
	pthread_exit(NULL);
}

int getHTTPRequestType(const char* receivedData)
{
	if(receivedData[0] == 'G')
		return (strncmp(receivedData, "GET", 3)==0)?1:0;
	else if(receivedData[0] == 'P')
	{
		if(receivedData[1] == 'O')
			return (strncmp(receivedData, "POST", 4)==0)?2:0;
		else
			return (strncmp(receivedData, "PATCH", 5)==0)?5:0;
	}
	else if(receivedData[0] == 'H')
		return (strncmp(receivedData, "HEAD", 4)==0)?3:0;
	else if(receivedData[0] == 'D')
		return (strncmp(receivedData, "DELETE", 6)==0)?4:0;
	else if(receivedData[0] == 'T')
		return (strncmp(receivedData, "TRACE", 5)==0)?6:0;
	else if(receivedData[0] == 'C')
		return (strncmp(receivedData, "CONNECT", 7)==0)?7:0;
	else
		return 0;
}

void setupResponse(struct HTTP_response** destination, int options)
{
#define SERVER_HEADER_DEFAULT "nginx/1.18.0 (Ubuntu)\0"
#define DATE_HEADER_DEFAULT "Wed, 29 Jan 2025 23:45:35 GMT\0"
#define CONTENTTYPE_HEADER_DEFAULT "text/html\0"
#define LASTMODIFIED_HEADER_DEFAULT "Wed, 29 Jan 2025 23:45:35 GMT\0"
#define CONNECTION_HEADER_DEFAULT "keep-alive\0"
#define ETAG_HEADER_DEFAULT "W/\"641b16b8-1404\"\0"
#define REFERRERPOLICY_HEADER_DEFAULT "strict-origin-when-cross-origin\0"
#define XCONTENTTYPEOPTIONS_HEADER_DEFAULT "nosniff\0"
#define CONTENTENCODING_HEADER_DEFAULT "gzip\0"

	struct HTTP_response* response  = (struct HTTP_response*)malloc(sizeof(struct HTTP_response) + (RESPONSE_HEADER_COUNT*sizeof(struct header)));
	*destination = response;
	strcpy(response->response_version, "HTTP/1.1\0");
	strcpy(response->status_code, "200 OK\0");

	response->headers[0].header_name = (char*)malloc(sizeof("Server\0"));
	strcpy(response->headers[0].header_name, "Server\0");
	response->headers[0].header_data = (char*)malloc(sizeof(SERVER_HEADER_DEFAULT));
	strcpy(response->headers[0].header_data, SERVER_HEADER_DEFAULT);

	response->headers[1].header_name = (char*)malloc(sizeof("Date\0"));
	strcpy(response->headers[1].header_name, "Date\0");
	response->headers[1].header_data = (char*)malloc(sizeof(DATE_HEADER_DEFAULT));
	strcpy(response->headers[1].header_data, DATE_HEADER_DEFAULT);

	response->headers[2].header_name = (char*)malloc(sizeof("Content-Type\0"));
	strcpy(response->headers[2].header_name, "Content-Type\0");
	response->headers[2].header_data = (char*)malloc(sizeof(CONTENTTYPE_HEADER_DEFAULT));
	strcpy(response->headers[2].header_data, CONTENTTYPE_HEADER_DEFAULT);

	response->headers[3].header_name = (char*)malloc(sizeof("Last-Modified\0"));
	strcpy(response->headers[3].header_name, "Last-Modified\0");
	response->headers[3].header_data = (char*)malloc(sizeof(LASTMODIFIED_HEADER_DEFAULT));
	strcpy(response->headers[3].header_data, LASTMODIFIED_HEADER_DEFAULT);

	response->headers[4].header_name = (char*)malloc(sizeof("Connection\0"));
	strcpy(response->headers[4].header_name, "Connection\0");
	response->headers[4].header_data = (char*)malloc(sizeof(CONNECTION_HEADER_DEFAULT));
	strcpy(response->headers[4].header_data, CONNECTION_HEADER_DEFAULT);

	response->headers[5].header_name = (char*)malloc(sizeof("ETag\0"));
	strcpy(response->headers[5].header_name, "ETag\0");
	response->headers[5].header_data = (char*)malloc(sizeof(ETAG_HEADER_DEFAULT));
	strcpy(response->headers[5].header_data, ETAG_HEADER_DEFAULT);

	response->headers[6].header_name = (char*)malloc(sizeof("Referrer-Policy\0"));
	strcpy(response->headers[6].header_name, "Referrer-Policy\0");
	response->headers[6].header_data = (char*)malloc(sizeof(REFERRERPOLICY_HEADER_DEFAULT));
	strcpy(response->headers[6].header_data, REFERRERPOLICY_HEADER_DEFAULT);

	response->headers[7].header_name = (char*)malloc(sizeof("X-Content-Type-Options\0"));
	strcpy(response->headers[7].header_name, "X-Content-Type-Options\0");
	response->headers[7].header_data = (char*)malloc(sizeof(XCONTENTTYPEOPTIONS_HEADER_DEFAULT));
	strcpy(response->headers[7].header_data, XCONTENTTYPEOPTIONS_HEADER_DEFAULT);

	response->headers[8].header_name = (char*)malloc(sizeof("Content-Encoding\0"));
	strcpy(response->headers[8].header_name, "Content-Encoding\0");
	response->headers[8].header_data = (char*)malloc(sizeof(CONTENTENCODING_HEADER_DEFAULT));
	strcpy(response->headers[8].header_data, CONTENTENCODING_HEADER_DEFAULT);

	response->headers[9].header_name = NULL;
	response->headers[9].header_data = NULL;
}
