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

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "otherFunctions.h"
#include "packetFunctions.h"

void analyzeCaughtPacket(unsigned char *user_args, const struct pcap_pkthdr *cap_header,
						 const unsigned char *packet)
{
	// initialize local variables
	const char function_name[] = "analyzeCaughtPacket";
	int status;

	int tcp_header_length, total_header_size = 0;
	unsigned char *pkt_data;

	// use user arguments
	struct pcap_handler_arguments *args = *(struct pcap_handler_arguments **)user_args;
	FILE *output_file_ptr = args->output_file_ptr;
	FILE *raw_output_file_ptr = args->raw_output_file_ptr;

	// initialize allocated pointers list
	struct allocated_pointers *pointers_head = NULL;
	pointers_head = (struct allocated_pointers *)malloc(sizeof(struct allocated_pointers));
	if(pointers_head == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	pointers_head->next_pointer = NULL;

	struct packet_structure *structured_packet;
	structured_packet = (struct packet_structure *)malloc(sizeof(struct packet_structure));
	if(structured_packet == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	add_new_pointer(pointers_head, NULL, structured_packet);
	memset(structured_packet, 0, sizeof(struct packet_structure));

	fprintf(output_file_ptr, "[%d] Got a %d byte packet\n", args->captured_count, cap_header->len);

	// ============================ get link layer ===================================
	status = getLinkLayerHeader(&(structured_packet->packet_type), &(structured_packet->link_layer_header),
					   pointers_head, packet, args->captured_count, output_file_ptr,
					   raw_output_file_ptr, cap_header->len, &total_header_size);
	if(status == -1)
	{
		printf("%s\n", error_message);
		return;
	}

	// ============================ get network layer ===================================
	status = getNetworkLayerHeader(&(structured_packet->packet_type), &(structured_packet->network_layer_header),
					   pointers_head, packet, args->captured_count, output_file_ptr,
					   raw_output_file_ptr, cap_header->len, &total_header_size);
	if(status == -1)
	{
		printf("%s\n", error_message);
		return;
	}

	// ============================ get transport layer ===================================

	pkt_data = (unsigned char *)(packet + total_header_size);

	// ============================ get application layer ===================================
	struct dns_query *query_ptr = NULL;

	if(ip_header->ip_type == IP_TYPE_UDP)
	{
		status = getDnsQuery(pkt_data, &query_ptr);

		if(status == 0)
			saveRemainingBytes((cap_header->len) - total_header_size, structured_packet,
							   (unsigned char *)(packet + total_header_size));
		else if(status == -1)
		{
			free_all_pointers(pointers_head);
			printf("[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(output_file_ptr, "[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
			dump(packet, cap_header->len, raw_output_file_ptr);
			return;
		}
		else
		{
			structured_packet->packet_type |= DNS_QUERY_TYPE;
			structured_packet->application_layer_structure = query_ptr;
			structured_packet->remaining_bytes = NULL;
			structured_packet->remaining_length = 0;
		}
	}
	else
		saveRemainingBytes((cap_header->len) - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));

	fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
	dump(packet, cap_header->len, raw_output_file_ptr);
	args->packet_list_tail->next_packet = structured_packet;
	args->packet_list_tail = structured_packet;
	args->captured_count++;
	remove_all_from_list(pointers_head);
	return;
}

void save_remaining_bytes(const int length, struct packet_structure *structured_packet,
						  const unsigned char *remaining_bytes)
{
	structured_packet->remaining_length = length;
	structured_packet->remaining_bytes = (unsigned char *)malloc(length);
	memcpy(structured_packet->remaining_bytes, remaining_bytes, length);
}

void print_packet(const struct packet_structure *packet, FILE *output_file_ptr)
{
	// link layer
	printEthernetHeader(packet->ethernet_header, output_file_ptr);

	// network layer
	int network_type = packet->packet_type & NETWORK_LAYER_TYPE;
	if(network_type == IP_TYPE)
		printIPHeader((struct ip_hdr *)packet->network_layer_structure, output_file_ptr);

	// transport layer
	int transport_type = packet->packet_type & TRANSPORT_LAYER_TYPE;
	if(transport_type == TCP_TYPE)
		printTCPHeader((struct tcp_hdr *)packet->transport_layer_structure, output_file_ptr);
	else if(transport_type == UDP_TYPE)
		printUDPHeader((struct udp_hdr *)packet->transport_layer_structure, output_file_ptr);

	// application layer
	int application_type = packet->packet_type & APPLICATION_LAYER_TYPE;
	if(application_type == DNS_QUERY_TYPE)
		printDnsQuery((struct dns_query *)packet->application_layer_structure, output_file_ptr);
}

int getLinkLayerHeader(int *packet_type, void **link_layer_header_pp,
					   struct allocated_pointers *pointers_head, const unsigned char *packet,
					   const int captured_count, FILE *output_file_ptr, FILE *raw_output_file_ptr,
					   const int packet_length, int *total_header_size)
{
	const char function_name[] = "getLinkLayerHeader";
	int status;

	// try ethernet
	struct ether_hdr *ethernet_header = NULL;
	ethernet_header = (struct ether_hdr *)malloc(ETHER_HDR_LEN);
	if(ethernet_header == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	add_new_pointer(pointers_head, NULL, ethernet_header);

	status = getEthernetHeader(packet, ethernet_header);
	if(status == -1)
	{
		printf("[%d] Error: %s\n", captured_count, error_message);
		fprintf(output_file_ptr, "[%d] Error: %s\n", captured_count, error_message);
		fprintf(raw_output_file_ptr, "[%d] packet dump:\n", captured_count);
		dump(packet, packet_length, raw_output_file_ptr);
		return -1;
	}
	else if(status == 1)
	{
		*packet_type |= ETHERNET_TYPE;
		*link_layer_header_pp = ethernet_header;
		*total_header_size += ETHER_HDR_LEN;
		return 1;
	}
	free(ethernet_header);

	// try other protocols
	return 0;
}

int getNetworkLayerHeader(int *packet_type, void **network_layer_header_pp,
					   struct allocated_pointers *pointers_head, const unsigned char *packet,
					   const int captured_count, FILE *output_file_ptr, FILE *raw_output_file_ptr,
					   const int packet_length, int *total_header_size)
{
	const char function_name[] = "getNetworkLayerHeader";
	int status;

	if(packet_type && LINK_LAYER_TYPE != ETHERNET_TYPE)
	{
		perror(function_name);
		strcpy(error_message, "wrong link layer type");
		return -1;
	}

	struct ip_hdr *ip_header = NULL;
	ip_header = (struct ip_hdr *)malloc(IP_HDR_LEN);
	if(ip_header == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	add_new_pointer(pointers_head, NULL, ip_header);

	status = getIPHeader(packet + *total_header_size, ip_header);
	if(status == -1)
	{
		printf("[%d] Error: %s\n", captured_count, error_message);
		fprintf(output_file_ptr, "[%d] Error: %s\n", captured_count, error_message);
		fprintf(raw_output_file_ptr, "[%d] packet dump:\n", captured_count);
		dump(packet, packet_length, raw_output_file_ptr);
		return -1;
	}
	else if(status == 1)
	{
		*packet_type |= IP_TYPE;
		*network_layer_header_pp = ip_header;
		*total_header_size += IP_HDR_LEN;
		return 1;
	}

	return 0;
}

int getTransportLayerHeader(struct packet_structure* structured_packet, struct pcap_handler_arguments *args, struct allocated_pointers *pointers_head, int *total_header_size, const unsigned char *packet)
{
	const char function_name[] = "getTransportLayerHeader";
	int status;

	if(structured_packet->packet_type && NETWORK_LAYER_TYPE != IP_TYPE)
	{
		perror(function_name);
		strcpy(error_message, "wrong network layer type");
		return -1;
	}

	void *transport_layer_header;
	unsigned short checksum;

	if(((struct ip_hdr*)(structured_packet->network_layer_header))->ip_type == IP_TYPE_TCP)
	{
		transport_layer_header = (struct tcp_hdr *)malloc(TCP_HDR_LEN);
		if(transport_layer_header == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating memory");
			fatal(error_message, NULL, stdout);
		}
		add_new_pointer(pointers_head, NULL, transport_layer_header);

		int tcp_header_length;
		getTCPHeader(packet + *total_header_size, transport_layer_header, &tcp_header_length);
		structured_packet->transport_layer_header = transport_layer_header;
		structured_packet->packet_type |= TCP_TYPE;
		*total_header_size += tcp_header_length;

		status = tcpChecksumMatches(packet, &checksum);
		if(status == 0)
		{
			free_all_pointers(pointers_head);
			fprintf(output_file_ptr, "checksum doesn't match\n");
			fprintf(output_file_ptr, "TCP packet dropped.\n");
			fprintf(output_file_ptr, "expected: %hu\n", checksum);
			fprintf(output_file_ptr, "got: %hu\n", tcp_header->tcp_checksum);
			fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
			dump(packet, cap_header->len, raw_output_file_ptr);
			args->captured_count++;
			return;
		}
		else if(status == -1)
		{
			free_all_pointers(pointers_head);
			printf("[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(output_file_ptr, "[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
			dump(packet, cap_header->len, raw_output_file_ptr);
			return;
		}
	}

	else if(ip_header->ip_type == IP_TYPE_UDP)
	{
		udp_header = (struct udp_hdr *)malloc(UDP_HDR_LEN);
		if(udp_header == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating memory");
			fatal(error_message, NULL, stdout);
		}
		add_new_pointer(pointers_head, &pointers_tail, udp_header);

		getUDPHeader(packet + total_header_size, udp_header);
		structured_packet->transport_layer_structure = udp_header;
		structured_packet->packet_type |= UDP_TYPE;
		total_header_size += UDP_HDR_LEN;

		status = udpChecksumMatches(packet, &checksum);
		if(status == 0)
		{
			free_all_pointers(pointers_head);
			fprintf(output_file_ptr, "checksum doesn't match\n");
			fprintf(output_file_ptr, "UDP packet dropped.\n");
			fprintf(output_file_ptr, "expected: %hu\n", checksum);
			fprintf(output_file_ptr, "got: %hu\n", udp_header->udp_checksum);
			fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
			dump(packet, cap_header->len, raw_output_file_ptr);
			args->captured_count++;
			return;
		}
		else if(status == -1)
		{
			free_all_pointers(pointers_head);
			printf("[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(output_file_ptr, "[%d] Error: %s\n", args->captured_count, error_message);
			fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
			dump(packet, cap_header->len, raw_output_file_ptr);
			return;
		}
	}

	else
	{
		fprintf(output_file_ptr, "unknown type\n");
		saveRemainingBytes((cap_header->len) - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));

		remove_all_from_list(pointers_head);
		fprintf(raw_output_file_ptr, "[%d] packet dump:\n", args->captured_count);
		dump(packet, cap_header->len, raw_output_file_ptr);
		args->packet_list_tail->next_packet = structured_packet;
		args->packet_list_tail = structured_packet;
		args->captured_count++;
		return;
	}
}
