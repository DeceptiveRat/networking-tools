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

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define UDP_HDR_LEN 8
struct udp_hdr
{
    unsigned short udp_src_port;
    unsigned short udp_dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
};

char udp_checksum_matches(const unsigned char *header_start, unsigned short* checksum);
bool get_udp_header(const unsigned char *header_start, struct udp_hdr* destination_header);
void print_udp_header(const struct udp_hdr* udp_header, FILE* outputFilePtr);
