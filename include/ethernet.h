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

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
struct ether_hdr
{
	unsigned char ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type;
};

int getEthernetHeader(const unsigned char *ethernet_header_start,
					  struct ether_hdr *destination_header);
void printEthernetHeader(const struct ether_hdr *ethernet_header, FILE *outputFilePtr);
