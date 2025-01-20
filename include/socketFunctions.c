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

#include "socketFunctions.h"
#include "otherFunctions.h"

pthread_mutex_t mutex_outputFile = PTHREAD_MUTEX_INITIALIZER;

char domainNames[DOMAIN_NAME_COUNT][DOMAIN_NAME_LENGTH];
void setDomainNames()
{
	FILE *domainNameFile = NULL;
	domainNameFile = fopen(DOMAIN_NAME_FILE_NAME, "r");

	if(domainNameFile == NULL)
		fatal("opening file", "setDomainNames", stdout);

	for(int i = 0; i < DOMAIN_NAME_COUNT; i++)
		fscanf(domainNameFile, "%s", domainNames[i]);

	fclose(domainNameFile);
}

void setupConnectionResources(struct connectionResources *connections, int connectionCount, FILE *globalOutputFilePtr)
{
	for(int i = 0; i < connectionCount; i++)
	{
		FILE *outputFilePtr = 0;
		char fileName[OUTPUT_FILE_NAME_LENGTH];
		char filepath[] = OUTPUT_FILE_PATH;
		char connectionNumber[5];
		int filepath_length = strlen(filepath);
		strcpy(fileName, filepath);
		strcat(fileName, "connection ");
		itoa(i, connectionNumber);
		strcat(fileName, connectionNumber);
		strcat(fileName, " data exchange.log");
		outputFilePtr = fopen(fileName, "w");

		if(outputFilePtr == NULL)
			fatal("opening file", "setupConnectionResources", stdout);

		connections[i].shutDown = false;
		connections[i].outputFilePtr = outputFilePtr;

		// set up server arguments
		// connection info
		connections[i].serverArgs.socket = &connections[i].serverSocket;
		connections[i].serverArgs.connectionID = i;
		memcpy(connections[i].serverArgs.connectedTo, "server\0", NAME_LENGTH);
		connections[i].serverArgs.shutDown = &connections[i].shutDown;
		// read/write buffer info
		connections[i].serverArgs.writeBufferSize = &connections[i].dataFromServerSize;
		connections[i].serverArgs.readBufferSize = &connections[i].dataFromClientSize;
		connections[i].serverArgs.writeBuffer = connections[i].dataFromServer;
		connections[i].serverArgs.readBuffer = connections[i].dataFromClient;
		// file pointers
		connections[i].serverArgs.localOutputFilePtr = outputFilePtr;
		connections[i].serverArgs.globalOutputFilePtr = globalOutputFilePtr;
		// mutex locks
		connections[i].serverArgs.mutex_writeBufferSize = &connections[i].mutex_dataFromServerSize;
		connections[i].serverArgs.mutex_readBufferSize = &connections[i].mutex_dataFromClientSize;

		// set up client arguments
		// connection info
		connections[i].clientArgs.socket = &connections[i].clientSocket;
		connections[i].clientArgs.connectionID = i;
		memcpy(connections[i].clientArgs.connectedTo, "client\0", NAME_LENGTH);
		connections[i].clientArgs.shutDown = &connections[i].shutDown;
		// read/write buffer info
		connections[i].clientArgs.writeBufferSize = &connections[i].dataFromClientSize;
		connections[i].clientArgs.readBufferSize = &connections[i].dataFromServerSize;
		connections[i].clientArgs.writeBuffer = connections[i].dataFromClient;
		connections[i].clientArgs.readBuffer = connections[i].dataFromServer;
		// file pointers
		connections[i].clientArgs.localOutputFilePtr = outputFilePtr;
		connections[i].clientArgs.globalOutputFilePtr = globalOutputFilePtr;
		// mutex locks
		connections[i].clientArgs.mutex_writeBufferSize = &connections[i].mutex_dataFromClientSize;
		connections[i].clientArgs.mutex_readBufferSize = &connections[i].mutex_dataFromServerSize;
	}
}

pthread_mutex_t *setupMutexes()
{
	char functionName[] = "setupMutexes";
	pthread_mutex_t *mutexList = NULL;
	mutexList = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t) * MAX_CONNECTION_COUNT * 3);

	if(mutexList == NULL)
		fatal("creating mutexes", functionName, stdout);

	for(int i = 0; i < MAX_CONNECTION_COUNT * 3; i++)
	{
		if(pthread_mutex_init(&mutexList[i], NULL) != 0)
			fatal("initializing mutexes", functionName, stdout);
	}

	return mutexList;
}

void cleanMutexes(pthread_mutex_t *mutexes)
{
	for(int i = 0; i < MAX_CONNECTION_COUNT * 2; i++)
	{
		if(pthread_mutex_destroy(&mutexes[i]) != 0)
			fatal("destroying mutexes", "cleanMutexes", stdout);
	}

	free(mutexes);
}

void handleConnection()
{
	char functionName[] = "handleConnection";
	setDomainNames();

	FILE *outputFilePtr = 0;
	char path[OUTPUT_FILE_NAME_LENGTH];
	strcpy(path, OUTPUT_FILE_PATH);
	strcat(path, "all exchanges.log");
	outputFilePtr = fopen(path, "w");

	if(outputFilePtr == NULL)
		fatal("opening file", functionName, stdout);

	// initialize local variables
	const unsigned char connectionEstablishedResponse[CONNECTION_ESTABLISHED_MESSAGE_LENGTH + 1] = "HTTP/1.1 200 Connection Established\r\n\r\n\0";
	pthread_mutex_t *mutexes = setupMutexes();
	struct connectionResources connections[MAX_CONNECTION_COUNT];

	for(int i = 0; i < MAX_CONNECTION_COUNT; i++)
	{
		connections[i].mutex_dataFromClientSize = mutexes[i * 2];
		connections[i].mutex_dataFromServerSize = mutexes[i * 2 + 1];
	}

	setupConnectionResources(connections, MAX_CONNECTION_COUNT, outputFilePtr);
	int connectionCount = 0;

	// initialize variables for listening thread
	pthread_t listeningThread;
	int hostSocket = returnListeningSocket();
	int acceptedSocket;
	bool acceptedSocketPending;
	bool shutDownListeningSocket;
	pthread_mutex_t mutex_acceptedSocket = PTHREAD_MUTEX_INITIALIZER;
	struct listeningThreadParameters listeningThreadArgs;

	listeningThreadArgs.listeningSocket = hostSocket;
	listeningThreadArgs.acceptedSocket = &acceptedSocket;
	listeningThreadArgs.acceptedSocketPending = &acceptedSocketPending;
	listeningThreadArgs.shutDown = &shutDownListeningSocket;
	listeningThreadArgs.mutex_acceptedSocket = &mutex_acceptedSocket;

	// create listening thread
	pthread_create(&listeningThread, NULL, listeningThreadFunction, &listeningThreadArgs);

	while(!shutDownListeningSocket)
	{
		if(connectionCount == MAX_CONNECTION_COUNT)
		{
			shutDownListeningSocket = true;
		}

		// there is a new connection pending
		if(acceptedSocketPending && connectionCount < MAX_CONNECTION_COUNT)
		{
			struct connectionResources *temp = &connections[connectionCount];
			pthread_mutex_lock(&mutex_outputFile);
			printf("[   main   ] new connection made\n");
			fprintf(temp->outputFilePtr, "[   main   ] new connection made\n");
			fprintf(outputFilePtr, "[   main   ] new connection made\n");
			pthread_mutex_unlock(&mutex_outputFile);

			pthread_mutex_lock(&mutex_acceptedSocket);
			temp->clientSocket = acceptedSocket;
			acceptedSocketPending = false;
			pthread_mutex_unlock(&mutex_acceptedSocket);
			temp->dataFromClient[0] = '\0';
			temp->dataFromServer[0] = '\0';
			int receiveLength = recv(temp->clientSocket, temp->dataFromClient, BUFFER_SIZE, 0);

			if(receiveLength == -1)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
				{
					pthread_mutex_lock(&mutex_outputFile);
					printf("[   main   ] lost connection with %d:\n", connectionCount);
					fprintf(temp->outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
					fprintf(outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
					printf("[   main   ] resetting connection...\n");
					fprintf(temp->outputFilePtr, "[   main   ] resetting connection...\n");
					fprintf(outputFilePtr, "[   main   ] resetting connection...\n");
					pthread_mutex_unlock(&mutex_outputFile);
					close(temp->clientSocket);
					continue;
				}

				// clean up code
				for(int i = 0; i < MAX_CONNECTION_COUNT; i++)
					connections[i].shutDown = true;

				for(int i = 0; i < MAX_CONNECTION_COUNT * 2; i++)
					pthread_mutex_destroy(&mutexes[i]);

				//cleanupConnections(connections, connectionCount);
				pthread_mutex_destroy(&mutex_outputFile);
				fclose(outputFilePtr);
				cleanMutexes(mutexes);
				fatal("receiving from client", functionName, stdout);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[   main   ] received %d bytes from client %d\n", receiveLength, connectionCount);
			fprintf(temp->outputFilePtr, "[   main   ] received %d bytes from client %d\n", receiveLength, connectionCount);
			dump(temp->dataFromClient, receiveLength, temp->outputFilePtr);
			fprintf(outputFilePtr, "[   main   ] received %d bytes from client %d\n", receiveLength, connectionCount);
			dump(temp->dataFromClient, receiveLength, outputFilePtr);
			pthread_mutex_unlock(&mutex_outputFile);
			temp->dataFromClientSize = receiveLength;

			// send automatic response if HTTPS connection
			bool isHTTPS = isConnectMethod(temp->dataFromClient);

			// get information about server
			char destinationName[DESTINATION_NAME_LENGTH + 1];
			int functionResult = getDestinationName(temp->dataFromClient, destinationName, outputFilePtr);
			int nameOffset;

			if(functionResult == -1)
			{
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(temp->outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				printf("[   main   ] error finding host string\n");
				fprintf(temp->outputFilePtr, "[   main   ] error finding host string\n");
				fprintf(outputFilePtr, "[   main   ] error finding host string\n");
				pthread_mutex_unlock(&mutex_outputFile);
				close(temp->clientSocket);
				continue;
			}

			if(functionResult == -2)
			{
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(temp->outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				printf("[   main   ] error finding host domain\n");
				fprintf(temp->outputFilePtr, "[   main   ] error finding host domain\n");
				fprintf(outputFilePtr, "[   main   ] error finding host domain\n");
				pthread_mutex_unlock(&mutex_outputFile);
				close(temp->clientSocket);
				continue;
			}

			else
			{
				nameOffset = functionResult;
			}

			char destinationPort[DESTINATION_PORT_LENGTH + 1];
			functionResult = getDestinationPort(temp->dataFromClient + nameOffset, destinationPort, isHTTPS, outputFilePtr);

			if(functionResult == -1)
			{
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(temp->outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				printf("[   main   ] error finding port number\n");
				fprintf(temp->outputFilePtr, "[   main   ] error finding port number\n");
				fprintf(outputFilePtr, "[   main   ] error finding port number\n");
				pthread_mutex_unlock(&mutex_outputFile);
				close(temp->clientSocket);
				continue;
			}

			if(functionResult == -2)
			{
				pthread_mutex_lock(&mutex_outputFile);
				printf("[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(temp->outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				fprintf(outputFilePtr, "[   main   ] lost connection with %d:\n", connectionCount);
				printf("[   main   ] port found not number\n");
				fprintf(temp->outputFilePtr, "[   main   ] port found not number\n");
				fprintf(outputFilePtr, "[   main   ] port found not number\n");
				pthread_mutex_unlock(&mutex_outputFile);
				close(temp->clientSocket);
				continue;
			}

			struct addrinfo destinationAddressInformation = returnDestinationAddressInfo(destinationName, destinationPort, outputFilePtr);

			// create socket to destination
			temp->serverSocket = returnSocketToServer(destinationAddressInformation);

			pthread_mutex_lock(&mutex_outputFile);
			printf("[   main   ] established TCP connection with server\n");
			fprintf(temp->outputFilePtr, "[   main   ] established TCP connection with server\n");
			fprintf(outputFilePtr, "[   main   ] established TCP connection with server\n");
			pthread_mutex_unlock(&mutex_outputFile);

			if(isHTTPS)
			{
				temp->clientArgs.isHTTPS = true;
				temp->serverArgs.isHTTPS = true;

				if(sendString(temp->clientSocket, connectionEstablishedResponse, CONNECTION_ESTABLISHED_MESSAGE_LENGTH) == 0)
				{
					// clean up code
					for(int i = 0; i < MAX_CONNECTION_COUNT; i++)
						connections[i].shutDown = true;

					for(int i = 0; i < MAX_CONNECTION_COUNT * 2; i++)
						pthread_mutex_destroy(&mutexes[i]);

					//cleanupConnections(connections, connectionCount);
					pthread_mutex_destroy(&mutex_outputFile);
					fclose(outputFilePtr);
					cleanMutexes(mutexes);
					fatal("sending 200 connection established", functionName, stdout);
				}

				else
				{
					pthread_mutex_lock(&mutex_outputFile);
					printf("[   main   ] Sent 200 connection established\n");
					fprintf(temp->outputFilePtr, "[   main   ] Sent 200 connection established\n");
					fprintf(outputFilePtr, "[   main   ] Sent 200 connection established\n");
					pthread_mutex_unlock(&mutex_outputFile);
					temp->dataFromClientSize = 0;
				}
			}

			else
			{
				temp->clientArgs.isHTTPS = false;
				temp->serverArgs.isHTTPS = false;
			}

			// create threads
			pthread_create(&(connections[connectionCount].clientThread), NULL, threadFunction, &(connections[connectionCount].clientArgs));
			pthread_create(&(connections[connectionCount].serverThread), NULL, threadFunction, &connections[connectionCount].serverArgs);

			connectionCount++;
		}
	}

	// wait for all connections to terminate
	for(int i = 0; i < connectionCount; i++)
	{
		pthread_join(connections[i].clientThread, NULL);
		pthread_join(connections[i].serverThread, NULL);
	}

	// clean up code
	for(int i = 0; i < MAX_CONNECTION_COUNT * 2; i++)
		pthread_mutex_destroy(&mutexes[i]);

	//cleanupConnections(connections, connectionCount);
	fclose(outputFilePtr);
	cleanMutexes(mutexes);
	pthread_mutex_destroy(&mutex_outputFile);
}

/* create, bind, and return a listening socket */
int returnListeningSocket()
{
	char functionName[] = "returnListeningSocket";
	struct addrinfo hostAddrHint, *hostResult;
	int hostSocket;

	memset(&hostAddrHint, 0, sizeof(struct addrinfo));
	hostAddrHint.ai_family = AF_INET;
	hostAddrHint.ai_socktype = SOCK_STREAM;
	hostAddrHint.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, PORT, &hostAddrHint, &hostResult);
	hostSocket = socket(hostResult->ai_family, hostResult->ai_socktype, hostResult->ai_protocol);

	if(hostSocket == -1)
		fatal("creating host socket", functionName, stdout);

	int yes = 1;

	if(setsockopt(hostSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
		fatal("setsockopt", functionName, stdout);

	if(bind(hostSocket, hostResult->ai_addr, hostResult->ai_addrlen) == -1)
		fatal("binding socket", functionName, stdout);

	if(listen(hostSocket, 10) == -1)
		fatal("listening on socket", functionName, stdout);

	freeaddrinfo(hostResult);
	return hostSocket;
}

/*
 * create, connect, and return a socket to the client
 * returns -1 for timeout, -2 for error accepting, -3 for error finding client addres information
 */
int returnSocketToClient(const int listeningSocket)
{
	// set up timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = SERVER_TIMEOUT_VALUE;
	setsockopt(listeningSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
	int timeoutCount = 0;

	struct sockaddr clientAddress;
	socklen_t sin_size = sizeof(struct sockaddr);
	int socketToClient;

	while(1)
	{
		if(timeoutCount >= TIMEOUT_COUNT)
		{
			return -1;
		}

		socketToClient = accept(listeningSocket, &clientAddress, &sin_size);

		if(socketToClient == -1)
		{
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				timeoutCount++;

			else
			{
				printf("errno %d: ", errno);
				return -2;
			}
		}

		// got connection
		else
		{
			break;
		}
	}

	char clientAddressString[INET_ADDRSTRLEN];
	struct sockaddr_in clientAddress_in = *((struct sockaddr_in *)&clientAddress);

	if(inet_ntop(AF_INET, &clientAddress_in.sin_addr, clientAddressString, INET_ADDRSTRLEN) == NULL)
		return -3;

	printf("got connection from %s port %d\n", clientAddressString, clientAddress_in.sin_port);

	return socketToClient;
}

/* extract the destination name string from the HTTP request */
/* returns offset of name from start of data, or on error:	-1 when error finding the host string
															-2 when error finding host name end using domain names */
int getDestinationName(const unsigned char *receivedData, char *destinationNameBuffer, FILE *outputFilePtr)
{
	char *destinationNameStart, *destinationNameEnd;
	int destinationNameLength;
	int domainNameIndex = 0;

	destinationNameStart = strstr((char *)receivedData, "Host: ");

	if(destinationNameStart == NULL)
		return -1;

	destinationNameStart += 6;
	destinationNameEnd = NULL;

	while(destinationNameEnd == NULL)
	{
		// reached end of file without finding domain
		if(domainNameIndex == DOMAIN_NAME_COUNT)
			return -2;

		destinationNameEnd = strstr(destinationNameStart, domainNames[domainNameIndex]);
		domainNameIndex++;
	}

	// TODO: change for domain names that aren't exactly 3 characters long
	destinationNameEnd += 4;
	destinationNameLength = destinationNameEnd - destinationNameStart;

	strncpy(destinationNameBuffer, destinationNameStart, destinationNameLength);
	destinationNameBuffer[destinationNameLength] = '\0';

	pthread_mutex_lock(&mutex_outputFile);
	printf("destination name is: %s\n", destinationNameBuffer);
	fprintf(outputFilePtr, "destination name is: %s\n", destinationNameBuffer);
	pthread_mutex_unlock(&mutex_outputFile);
	return (char *)receivedData - destinationNameStart;
}

/* extract port number from request.
 * returns:
 * 		 0: sucess
 *		-1: error finding port number end (\r\n)
 *		-2: found port number is not a number
 */
int getDestinationPort(const unsigned char *destinationNameEnd, char *destinationPortBuffer, const bool isHTTPS, FILE *outputFilePtr)
{
	if(*destinationNameEnd == ':')
	{
		char *destinationPortEnd = strstr((char *)destinationNameEnd, "\r\n");

		if(destinationPortEnd == NULL)
			return -1;

		int destinationPortLength = destinationPortEnd - (char *)destinationNameEnd - 1;
		strncpy(destinationPortBuffer, (char *)(destinationNameEnd + 1), destinationPortLength);
		destinationPortBuffer[destinationPortLength] = '\0';

		if(!isNumber(destinationPortBuffer))
			return -2;
	}

	if(isHTTPS)
		strncpy(destinationPortBuffer, "443\0", 4);

	else
		strncpy(destinationPortBuffer, "80\0", 3);

	pthread_mutex_lock(&mutex_outputFile);
	printf("destination port is: %s\n", destinationPortBuffer);
	fprintf(outputFilePtr, "destination port is: %s\n", destinationPortBuffer);
	pthread_mutex_unlock(&mutex_outputFile);
	return 0;
}

/* get additional information about the destination */
struct addrinfo returnDestinationAddressInfo(const char *destinationName, const char *destinationPort, FILE *outputFilePtr)
{
	char functionName[] = "returnDestinationAddressInfo";
	struct addrinfo destinationAddressHint, *destinationAddressResult;
	memset(&destinationAddressHint, 0, sizeof(struct addrinfo));
	destinationAddressHint.ai_family = AF_INET;
	destinationAddressHint.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(destinationName, destinationPort, &destinationAddressHint, &destinationAddressResult) != 0)
		fatal("getting address information for the destination", functionName, stdout);

	char destinationAddressString[INET_ADDRSTRLEN];
	struct sockaddr_in destinationAddress_in = *(struct sockaddr_in *)destinationAddressResult->ai_addr;

	if(inet_ntop(AF_INET, &destinationAddress_in.sin_addr, destinationAddressString, INET_ADDRSTRLEN) == NULL)
		fatal("converting destination ip address to string", functionName, stdout);

	pthread_mutex_lock(&mutex_outputFile);
	printf("destination ip address: %s\n", destinationAddressString);
	fprintf(outputFilePtr, "destination ip address: %s\n", destinationAddressString);
	pthread_mutex_unlock(&mutex_outputFile);

	struct addrinfo destinationAddrInfo = *destinationAddressResult;
	freeaddrinfo(destinationAddressResult);

	return destinationAddrInfo;
}

/* create, connect, and return a socket to the server */
int returnSocketToServer(const struct addrinfo destinationAddressInformation)
{
	char functionName[] = "returnSocketToServer";
	int socketToDestination;
	socketToDestination = socket(destinationAddressInformation.ai_family, destinationAddressInformation.ai_socktype, destinationAddressInformation.ai_protocol);

	if(socketToDestination == -1)
		fatal("creating socket to server", functionName, stdout);

	if(connect(socketToDestination, destinationAddressInformation.ai_addr, destinationAddressInformation.ai_addrlen) == -1)
		fatal("connecting to server", functionName, stdout);

	return socketToDestination;
}

bool isConnectMethod(const unsigned char *receivedData)
{
	if(strstr((char *)receivedData, "CONNECT ") == NULL)
		return false;

	else
		return true;
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

void *threadFunction(void *args)
{
	// set up local variables with argument
	struct threadParameters parameters = *(struct threadParameters *)args;
	// connection info
	const int socket = *parameters.socket;
	const int ID = parameters.connectionID;
	char connectedTo[NAME_LENGTH];
	memcpy(connectedTo, parameters.connectedTo, NAME_LENGTH);
	bool *shutDown = parameters.shutDown;
	bool isHTTPS = parameters.isHTTPS;
	// read/write buffer info
	int *readBufferSize = parameters.readBufferSize;
	int *writeBufferSize = parameters.writeBufferSize;
	unsigned char *writeBuffer = parameters.writeBuffer;
	const unsigned char *readBuffer = parameters.readBuffer;
	// file pointers
	FILE *localOutputFilePtr = parameters.localOutputFilePtr;
	FILE *globalOutputFilePtr = parameters.globalOutputFilePtr;
	// mutex locks
	pthread_mutex_t *mutex_writeBuffer = parameters.mutex_writeBufferSize;
	pthread_mutex_t *mutex_readBuffer = parameters.mutex_readBufferSize;

	unsigned char tempReadBuffer[BUFFER_SIZE + 1];
	ssize_t recvResult;
	bool clientConnected = (connectedTo[0] == 'c') ? (true) : (false);

	// set up timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = CONNECTION_TIMEOUT_VALUE;
	setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
	int timeoutCount = 0;

	while(!(*shutDown))
	{
		// CONNECTION_TIMEOUT_VALUE seconds have passed idle
		if(timeoutCount >= TIMEOUT_COUNT)
		{
			*shutDown = true;
			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Terminating: idle connection\n", ID, connectedTo);
			fprintf(globalOutputFilePtr, "[%d - %s] Terminating: idle connection\n", ID, connectedTo);
			fprintf(localOutputFilePtr, "[%d - %s] Terminating: idle connection\n", ID, connectedTo);
			pthread_mutex_unlock(&mutex_outputFile);
			pthread_exit(NULL);
		}

		recvResult = recv(socket, tempReadBuffer, BUFFER_SIZE, 0);

		if(recvResult == -1)
		{
			// error reading data
			if(errno != EAGAIN && errno != EWOULDBLOCK)
			{
				*shutDown = true;
				pthread_mutex_lock(&mutex_outputFile);
				printf("[%d - %s] Terminating: Error reading data.\nErrno: %d\n", ID, connectedTo, errno);
				fprintf(globalOutputFilePtr, "[%d - %s] Terminating: Error reading data.\nErrno: %d\n", ID, connectedTo, errno);
				fprintf(localOutputFilePtr, "[%d - %s] Terminating: Error reading data.\nErrno: %d\n", ID, connectedTo, errno);
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
				*shutDown = true;
				pthread_mutex_lock(&mutex_outputFile);
				printf("[%d - %s] Terminating: 0 bytes received\n", ID, connectedTo);
				fprintf(globalOutputFilePtr, "[%d - %s] Terminating: 0 bytes received\n", ID, connectedTo);
				fprintf(localOutputFilePtr, "[%d - %s] Terminating: 0 bytes received\n", ID, connectedTo);
				pthread_mutex_unlock(&mutex_outputFile);
				pthread_exit(NULL);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Read %ld bytes\n", ID, connectedTo, recvResult);
			fprintf(globalOutputFilePtr, "[%d - %s] Read %ld bytes\n", ID, connectedTo, recvResult);
			fprintf(localOutputFilePtr, "[%d - %s] Read %ld bytes\n", ID, connectedTo, recvResult);
			dump(tempReadBuffer, recvResult, globalOutputFilePtr);
			dump(tempReadBuffer, recvResult, localOutputFilePtr);
			pthread_mutex_unlock(&mutex_outputFile);

			// wait until buffer is empty before writing to it
			while(*writeBufferSize != 0) {};

			// write to buffer and change buffer size
			pthread_mutex_lock(mutex_writeBuffer);

			memcpy(writeBuffer, tempReadBuffer, recvResult);

			*writeBufferSize = recvResult;

			pthread_mutex_unlock(mutex_writeBuffer);

			pthread_mutex_lock(&mutex_outputFile);

			printf("[%d - %s] Wrote %ld bytes\n", ID, connectedTo, recvResult);

			fprintf(globalOutputFilePtr, "[%d - %s] Wrote %ld bytes\n", ID, connectedTo, recvResult);

			fprintf(localOutputFilePtr, "[%d - %s] Wrote %ld bytes\n", ID, connectedTo, recvResult);

			pthread_mutex_unlock(&mutex_outputFile);
		}

		// if there is data in the read buffer, send it
		if(*readBufferSize != 0)
		{
			if(sendString(socket, readBuffer, *readBufferSize) == 0)
			{
				pthread_mutex_lock(&mutex_outputFile);
				*shutDown = true;
				printf("[%d - %s] Terminating: error sending data\n", ID, connectedTo);
				fprintf(globalOutputFilePtr, "[%d - %s] Terminating: error sending data\n", ID, connectedTo);
				fprintf(localOutputFilePtr, "[%d - %s] Terminating: error sending data\n", ID, connectedTo);
				pthread_mutex_unlock(&mutex_outputFile);
				pthread_exit(NULL);
			}

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Sent data\n", ID, connectedTo);
			fprintf(globalOutputFilePtr, "[%d - %s] Sent data\n", ID, connectedTo);
			fprintf(localOutputFilePtr, "[%d - %s] Sent data\n", ID, connectedTo);
			pthread_mutex_unlock(&mutex_outputFile);

			pthread_mutex_lock(mutex_readBuffer);
			*readBufferSize = 0;
			pthread_mutex_unlock(mutex_readBuffer);

			pthread_mutex_lock(&mutex_outputFile);
			printf("[%d - %s] Set buffer to empty\n", ID, connectedTo);
			fprintf(globalOutputFilePtr, "[%d - %s] Set buffer to empty\n", ID, connectedTo);
			fprintf(localOutputFilePtr, "[%d - %s] Set buffer to empty\n", ID, connectedTo);
			pthread_mutex_unlock(&mutex_outputFile);
		}
	}

	// clean up code
	close(socket);
	pthread_mutex_lock(&mutex_outputFile);
	printf("[%d - %s] Terminating: shutdown variable set\n", ID, connectedTo);
	fprintf(globalOutputFilePtr, "[%d - %s] Terminating: shutdown variable set\n", ID, connectedTo);
	fprintf(localOutputFilePtr, "[%d - %s] Terminating: shutdown variable set\n", ID, connectedTo);
	pthread_mutex_unlock(&mutex_outputFile);
	pthread_exit(NULL);
}

void *listeningThreadFunction(void *args)
{
	struct listeningThreadParameters parameter = *(struct listeningThreadParameters *)args;
	int listeningSocket = parameter.listeningSocket;
	int *acceptedSocket = parameter.acceptedSocket;
	bool *acceptedSocketPending = parameter.acceptedSocketPending;
	bool *shutDown = parameter.shutDown;
	pthread_mutex_t *mutex_acceptedSocket = parameter.mutex_acceptedSocket;

	int tempAcceptedSocket = 0;

	printf("[ listener ] Listening on port %s\n", PORT);

	while(!(*shutDown))
	{
		if(tempAcceptedSocket == 0)
			tempAcceptedSocket = returnSocketToClient(listeningSocket);

		if(tempAcceptedSocket == -1)
		{
			printf("[ listener ] accepting connection timed out\n");
			*shutDown = true;
			continue;
		}

		else if(tempAcceptedSocket == -2)
		{
			printf("[ listener ] error while accepting connection\n");
			*shutDown = true;
			continue;
		}

		else if(tempAcceptedSocket == -3)
		{
			printf("[ listener ] error finding client address information\n");
			*shutDown = true;
			continue;
		}

		pthread_mutex_lock(mutex_acceptedSocket);

		if(!(*acceptedSocketPending))
		{
			*acceptedSocket = tempAcceptedSocket;
			*acceptedSocketPending = true;
			tempAcceptedSocket = 0;
		}

		pthread_mutex_unlock(mutex_acceptedSocket);

	}

	if(tempAcceptedSocket != 0)
		close(tempAcceptedSocket);

	pthread_mutex_lock(mutex_acceptedSocket);

	if(!(*acceptedSocketPending))
		close(*acceptedSocket);

	pthread_mutex_unlock(mutex_acceptedSocket);
	close(listeningSocket);
	pthread_exit(NULL);
}

void cleanupConnections(struct connectionResources *conRes, int connectionCount)
{
	void *retval;
	int result;

	for(int i = 0; i < connectionCount; i++)
	{
		fclose(conRes[i].outputFilePtr);
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
	if(strstr((char *)requestMessage, "GET ") == NULL)
	{
		requestedObject[0] = '\0';
		return;
	}

	char *requestedObjectEnd = strstr((char *)requestMessage, " HTTP/");

	if(requestedObjectEnd == NULL)
	{
		requestedObject[0] = '\0';
		return;
	}

	else
	{
		int nameLength = requestedObjectEnd - (char *)requestMessage;
		strncpy(requestedObject, (char *)requestMessage, nameLength);
		requestedObject[nameLength] = '\0';
		return;
	}
}
