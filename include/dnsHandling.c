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

#include <stdlib.h>
#include <string.h>

#include "dnsHandling.h"
#include "otherFunctions.h"

#define DNS_MAX_CONNECTION_COUNT 10


void initializeDNSProxy()
{
#define DNS_OUTPUT_FILE_NAME_LENGTH 40
#define DNS_OUTPUT_FILE_PATH "logs/"
#define SOCKET_COUNT 1

	char function_name[] = "handleDNSConnection";
	// set up output file
	FILE *output_file_ptr = 0;
	char path[DNS_OUTPUT_FILE_NAME_LENGTH];
	strcpy(path, DNS_OUTPUT_FILE_PATH);
	strcat(path, "dns.log");
	output_file_ptr = fopen(path, "w");
	if(output_file_ptr == NULL)
		fatal("opening file", function_name, stdout);

	// set up local variables
	int status;
	int IPv4_listening_socket;
	status = returnUDPListeningSocket(&IPv4_listening_socket, AF_INET);
	if(status == -1)
	{
		fprintf(stdout, "%s\n", error_message);
		fprintf(stdout, "cleaning up...\n");
		fclose(output_file_ptr);
		fprintf(stdout, "terminating...\n");
		exit(-1);
	}

	status = returnEpollInstance(SOCKET_COUNT, IPv4_listening_socket);
	if(status == -1)
	{
		fprintf(stdout, "%s\n", error_message);
		fprintf(stdout, "cleaning up...\n");
		fclose(output_file_ptr);
		fprintf(stdout, "terminating...\n");
		exit(-1);
	}

	int epoll_fd = status;
	status = handleDNSConnection(epoll_fd, SOCKET_COUNT, output_file_ptr);
	if(status == -1)
	{
		fprintf(stdout, "%s\n", error_message);
		fprintf(stdout, "cleaning up...\n");
		fclose(output_file_ptr);
		fprintf(stdout, "terminating...\n");
		exit(-1);
	}
	else
	{
		fprintf(stdout, "%s\n", error_message);
		fprintf(stdout, "cleaning up...\n");
		fclose(output_file_ptr);
		fprintf(stdout, "terminating...\n");
		exit(0);
	}
}

int returnUDPListeningSocket(int* destination_socket, int address_family)
{
	char function_name[] = "returnUDPListeningSocket";
	int status;
	struct addrinfo hints;
	struct addrinfo *results;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = address_family;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo("localhost", DNS_LISTENING_PORT, &hints, &results);
	if(status != 0)
	{
		perror(function_name);
		strcpy(error_message, "getting address info for listening socket");
		return -1;
	}

	int listening_socket;
	status = socket(results->ai_family, results->ai_socktype | SOCK_DGRAM, results->ai_protocol);
	if(status == -1)
	{
		perror(function_name);
		strcpy(error_message, "creating listening socket");
		return -1;
	}
	listening_socket = status;

	int yes = 1;
	status = setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if(status == -1)
	{
		perror(function_name);
		strcpy(error_message, "setting socket option for listening socket");
		return -1;
	}
	status = bind(listening_socket, results->ai_addr, results->ai_addrlen);
	if(status == -1)
	{
		perror(function_name);
		strcpy(error_message, "binding listening socket");
		return -1;
	}
	*destination_socket = listening_socket;
	freeaddrinfo(results);

	return 0;
}

int handleDNSConnection(int epoll_fd, int socket_count, FILE *output_file_ptr)
{
	char function_name[] = "handleDNSConnection";
	if(SIGINTSetsExitFlag() == -1)
		return -1;

	struct epoll_event *events;
	events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * socket_count);
	if(events == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory for events");
		return -1;
	}

	while(!exitFlagSet())
	{
		int ready_count = epoll_wait(epoll_fd, events, socket_count, -1);
		if(ready_count == -1)
		{
			perror(function_name);
			strcpy(error_message, "calling epoll_wait");
			return -1;
		}

		for(int i = 0; i < ready_count; i++)
		{
			int socket_fd = events[i].data.fd;
			struct sockaddr_storage client_addr;
			socklen_t addr_len = sizeof(client_addr);
			char buffer[BUFFER_SIZE];

			ssize_t bytes_received = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0,
											  (struct sockaddr *)&client_addr, &addr_len);

			if(bytes_received == 0)
				continue;
			
			buffer[bytes_received] = '\0';
			char client_IP[INET6_ADDRSTRLEN];
			if(client_addr.ss_family == AF_INET)
			{
				struct sockaddr_in *addr = (struct sockaddr_in *)&client_addr;
				inet_ntop(client_addr.ss_family, &(addr->sin_addr), client_IP, sizeof(client_IP));
			}
			else if(client_addr.ss_family == AF_INET6)
			{
				struct sockaddr_in6 *addr = (struct sockaddr_in6*)&client_addr;
				inet_ntop(client_addr.ss_family, &(addr->sin6_addr), client_IP, sizeof(client_IP));
			}
			else
			{
				strcpy(error_message, "invalid address family returned by recvfrom");
				return -1;
			}

			fprintf(stdout, "Received %ld packet from %s:\n", bytes_received, client_IP);
			fprintf(output_file_ptr, "Received %ld packet from %s:\n", bytes_received, client_IP);
			dump((unsigned char*)buffer, bytes_received, stdout);
			dump((unsigned char*)buffer, bytes_received, output_file_ptr);

			struct dns_query* dns_structure;
			if(get_dns_query((unsigned char*)buffer, &dns_structure) == false)
				continue;
			print_dns_query(dns_structure, stdout);
			print_dns_query(dns_structure, output_file_ptr);
			freeDnsQuery(dns_structure);
		}
	}

	free(events);
	if(SIGINTDefault() == -1)
		return -1;

	return 0;
}

int returnEpollInstance(int socket_count, ...)
{
	va_list arguments;
	va_start(arguments, socket_count);

	int epoll_fd = epoll_create1(0);
	if(epoll_fd == -1)
		return -1;

	struct epoll_event event;
	event.events = EPOLLIN;
	for(int i = 0; i < socket_count; i++)
	{
		int socket = va_arg(arguments, int);
		event.data.fd = socket;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket, &event);
	}

	va_end(arguments);

	return epoll_fd;
}
