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
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define TCP_HDR_LEN 20
struct tcp_hdr
{
	unsigned short tcp_src_port;
	unsigned short tcp_dest_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	// assuming little endian
	unsigned char tcp_reserved_4 : 4;
	unsigned char tcp_offset : 4;
	unsigned char tcp_flags; // the first 2 bits are reserved
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent;
};

struct tcp_hdr_options
{
	// work in progress
};

int tcpChecksumMatches(const unsigned char *packet_start, unsigned short *checksum);
int getTCPHeader(const unsigned char *packet_start, const int data_offset, struct tcp_hdr *destination_header,
				 int *tcp_header_size);
void printTCPHeader(const struct tcp_hdr *tcp_header, FILE *outputFilePtr);
