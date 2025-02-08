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

#define UDP_HDR_LEN 8
struct udp_hdr
{
	unsigned short udp_src_port;
	unsigned short udp_dest_port;
	unsigned short udp_length;
	unsigned short udp_checksum;
};

int udpChecksumMatches(const unsigned char *packet_start, unsigned short *checksum);
int getUDPHeader(const unsigned char *packet_start, const int data_offset, struct udp_hdr *destination_header);
void printUDPHeader(const struct udp_hdr *udp_header, FILE *outputFilePtr);
