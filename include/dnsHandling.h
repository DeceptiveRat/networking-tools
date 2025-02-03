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
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "dns.h"

#define DNS_LISTENING_PORT "5353"
#define BUFFER_SIZE 2048

void initializeDNSProxy();
int handleDNSConnection(int epoll_fd, int socket_count, FILE* output_file_ptr);
int returnUDPListeningSocket(int* destination_socket, int address_family);
int returnEpollInstance(int socket_count, ...);
