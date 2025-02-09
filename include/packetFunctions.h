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

#include "dns.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

#define LINK_LAYER_TYPE 0xff000000
#define ETHERNET_TYPE 0x01000000
#define NETWORK_LAYER_TYPE 0xff0000
#define IP_TYPE 0x010000
#define TRANSPORT_LAYER_TYPE 0xff00
#define TCP_TYPE 0x0100
#define UDP_TYPE 0x0200
#define APPLICATION_LAYER_TYPE 0xff
#define DNS_QUERY_TYPE 0x01
#define DNS_RESPONSE_TYPE 0x02
#define HTTP_TYPE 0x04

// =================================== structures =============================================
struct pcap_handler_arguments
{
	FILE *output_file_ptr;
	FILE *raw_output_file_ptr;
	struct packet_structure *packet_list_head;
	struct packet_structure *packet_list_tail;
	int captured_count;
};

struct packet_structure
{
	int packet_type;
	void *link_layer_header;
	void *network_layer_header;
	void *transport_layer_header;
	void *application_layer_header;
	unsigned char *remaining_bytes;
	int remaining_length;
	struct packet_structure *next_packet;
};

void saveCaughtPacket(unsigned char *user_args, const struct pcap_pkthdr *cap_header,
						 const unsigned char *packet);
int saveRemainingBytes(const int length, struct packet_structure *saved_packet,
					   const unsigned char *remaining_bytes);
int printPacket(const struct packet_structure *packet, FILE *outputFilePtr);
int getLinkLayerHeader(int *packet_type, void **link_layer_header_pp,
					   const unsigned char *packet,
					   const int captured_count, FILE *output_file_ptr, FILE *raw_output_file_ptr,
					   const int packet_length, int *total_header_size);
int getNetworkLayerHeader(int *packet_type, void **network_layer_header_pp,
					   const unsigned char *packet,
					   const int captured_count, FILE *output_file_ptr, FILE *raw_output_file_ptr,
					   const int packet_length, int *total_header_size);
int getTransportLayerHeader(struct packet_structure* structured_packet, struct pcap_handler_arguments *args, int *total_header_size, const unsigned char *packet, const int packet_length);
int getApplicationLayerHeader(struct packet_structure* structured_packet, struct pcap_handler_arguments *args, int *total_header_size, const unsigned char *packet, const int packet_length);
