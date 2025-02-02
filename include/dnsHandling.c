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

#include <string.h>
#include <stdlib.h>

#include "dnsHandling.h"
#include "otherFunctions.h"

#define DNS_MAX_CONNECTION_COUNT 10

void initializeDNSProxy()
{
#define DNS_OUTPUT_FILE_NAME_LENGTH 40
#define DNS_OUTPUT_FILE_PATH "logs/"

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
	int connection_count = 0;
	int IPv4_listening_socket;
	int IPv6_listening_socket;
	int status = returnUDPListeningSocket(&IPv4_listening_socket, &IPv6_listening_socket);
}

int returnUDPListeningSocket(int* IPv4_listening_socket, int* IPv6_listening_socket)
{
	int status;
	struct addrinfo hints;
	struct addrinfo* results;

	// get IPv4 socket
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if(getaddrinfo("localhost", DNS_LISTENING_PORT, &hints, &results) != 0)
	{
		fatal("getting address info for listening socket", "returnUDPListeningSocket", stdout);
		return -1;
	}
	
	int listening_socket = socket(results->ai_family, results->ai_socktype | SOCK_DGRAM, results->ai_protocol);

	int yes = 1;
	if(setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
	{
		fatal("setting socket option", "returnUDPListeningSocket", stdout);
		return -1;
	}
	bind(listening_socket, results->ai_addr, results->ai_addrlen);
	*IPv4_listening_socket = listening_socket;
	freeaddrinfo(results);

	// get IPv6 socket
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	if(getaddrinfo("localhost", DNS_LISTENING_PORT, &hints, &results) != 0)
	{
		fatal("getting address info for listening socket", "returnUDPListeningSocket", stdout);
		return -1;
	}
	
	listening_socket = socket(results->ai_family, results->ai_socktype | SOCK_DGRAM, results->ai_protocol);

	if(setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
	{
		fatal("setting socket option", "returnUDPListeningSocket", stdout);
		return -1;
	}
	bind(listening_socket, results->ai_addr, results->ai_addrlen);
	*IPv6_listening_socket = listening_socket;
	freeaddrinfo(results);

	return 0;
}

void handleDNSConnection(int listening_socket, FILE* output_file_ptr)
{
	// use epoll to accept connections and handle them
}
