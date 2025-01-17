/*
 * This file is part of BPS.
 *
 * BPS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with BPS.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>

#include "packetFunctions.h"
#include "otherFunctions.h"

void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet)
{
	// initialize local variables
	const char functionName[] = "analyze_caught_packet";
	int tcp_header_length, total_header_size;
	unsigned char *pkt_data;

	// use user arguments
	struct pcap_handler_arguments* args = *(struct pcap_handler_arguments**)user_args;
	FILE* outputFilePtr = args->outputFilePtr;
	FILE* rawOutputFilePtr = args->rawOutputFilePtr;

	// initialize allocated pointers list
	struct allocated_pointers* head = NULL;
	head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));
	if(head == NULL)
		fatal("allocating memory for clean up head", functionName, NULL);
	head->next_pointer = NULL;
	struct allocated_pointers* tail = head;

	// ethernet_packet structure to store current packet
	struct packet_structure* saved_packet;
	saved_packet = (struct packet_structure*)malloc(sizeof(struct packet_structure));
	if(saved_packet == NULL)
		fatal("allocating memory for saved_packet", functionName, outputFilePtr);
	add_new_pointer(head, &tail, saved_packet);
	memset(saved_packet, 0, sizeof(struct packet_structure));

	fprintf(outputFilePtr, "[%d] Got a %d byte packet\n", args->captured_count, cap_header->len);

	// ============================ get link layer ===================================
	struct ether_hdr* ethernet_header = NULL;
	ethernet_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN);
	if(ethernet_header == NULL)
		fatal("allocating memory: ethernet_header", functionName, outputFilePtr);
	add_new_pointer(head, &tail, ethernet_header);

	// verify if it is ethernet later
	get_ethernet_header(packet, ethernet_header);
	saved_packet->packet_type |= ETHERNET_TYPE;
	saved_packet->ethernet_header = ethernet_header;
	total_header_size = ETHER_HDR_LEN;

	// ============================ get network layer ===================================
	struct ip_hdr* ip_header = NULL;
	ip_header = (struct ip_hdr*)malloc(IP_HDR_LEN);
	if(ip_header == NULL)
		fatal("allocating memory: ip_header", functionName, outputFilePtr);
	add_new_pointer(head, &tail, ip_header);

	// verify if it is IP later
	get_ip_header(packet + total_header_size, ip_header);
	saved_packet->packet_type |= IP_TYPE;
	saved_packet->network_layer_structure = ip_header;
	total_header_size += IP_HDR_LEN;

	// ============================ get transport layer ===================================
	struct tcp_hdr* tcp_header = NULL;
	struct udp_hdr* udp_header = NULL;
	unsigned short checksum;

	if(ip_header->ip_type == IP_TYPE_TCP)
	{
		tcp_header = (struct tcp_hdr*)malloc(TCP_HDR_LEN);
		if(tcp_header == NULL)
			fatal("allocating memory: tcp_header", functionName, outputFilePtr);
		add_new_pointer(head, &tail, tcp_header);

		get_tcp_header(packet + total_header_size, tcp_header, &tcp_header_length);
		saved_packet->transport_layer_structure = tcp_header;
		saved_packet->packet_type |= TCP_TYPE;
		total_header_size += tcp_header_length;

		if(tcp_checksum_matches(packet, &checksum) != 1)
		{
			fprintf(outputFilePtr, "checksum doesn't match\n");
			fprintf(outputFilePtr, "TCP packet dropped.\n");
			fprintf(outputFilePtr, "expected: %hu\n", checksum);
			fprintf(outputFilePtr, "got: %hu\n", tcp_header->tcp_checksum);
			fprintf(rawOutputFilePtr, "[%d] packet dump:\n", args->captured_count);
			hex_stream_dump(packet, cap_header->len, rawOutputFilePtr);
			args->captured_count++;
			free_all_pointers(head);
			return;
		}

	}

	else if(ip_header->ip_type == IP_TYPE_UDP)
	{
		udp_header = (struct udp_hdr*)malloc(UDP_HDR_LEN);
		if(udp_header == NULL)
			fatal("allocating memory: udp_header", functionName, outputFilePtr);
		add_new_pointer(head, &tail, udp_header);

		get_udp_header(packet + total_header_size, udp_header);
		saved_packet->transport_layer_structure = udp_header;
		saved_packet->packet_type |= UDP_TYPE;
		total_header_size += UDP_HDR_LEN;

		if(udp_checksum_matches(packet, &checksum) != 1)
		{
			fprintf(outputFilePtr, "checksum doesn't match\n");
			fprintf(outputFilePtr, "UDP packet dropped.\n");
			fprintf(outputFilePtr, "expected: %hu\n", checksum);
			fprintf(outputFilePtr, "got: %hu\n", udp_header->udp_checksum);
			fprintf(rawOutputFilePtr, "[%d] packet dump:\n", args->captured_count);
			hex_stream_dump(packet, cap_header->len, rawOutputFilePtr);
			args->captured_count++;
			free_all_pointers(head);
			return;
		}
	}

	else
	{
		fprintf(outputFilePtr, "unknown type\n");
		save_remaining_bytes((cap_header->len) - total_header_size, saved_packet, (unsigned char*)(packet + total_header_size));

		fprintf(rawOutputFilePtr, "[%d] packet dump:\n", args->captured_count);
		hex_stream_dump(packet, cap_header->len, rawOutputFilePtr);
		args->packet_list_tail->next_packet = saved_packet;
		args->packet_list_tail = saved_packet;
		args->captured_count++;
		remove_all_from_list(head);
		return;
	}

	pkt_data = (unsigned char *)(packet + total_header_size);

	// ============================ get application layer ===================================
	struct dns_query* query_ptr = NULL;

	if(ip_header->ip_type == IP_TYPE_UDP)
	{
		bool result = true;
		result = get_dns_query(pkt_data, &query_ptr);

		// not dns query
		if(result == false)
			save_remaining_bytes((cap_header->len) - total_header_size, saved_packet, (unsigned char*)(packet + total_header_size));
		else
		{
			saved_packet->packet_type |= DNS_QUERY_TYPE;
			saved_packet->application_layer_structure = query_ptr;
			saved_packet->remaining_bytes = NULL;
			saved_packet->remaining_length = 0;
		}
	}
	else
		save_remaining_bytes((cap_header->len) - total_header_size, saved_packet, (unsigned char*)(packet + total_header_size));

	fprintf(rawOutputFilePtr, "[%d] packet dump:\n", args->captured_count);
	hex_stream_dump(packet, cap_header->len, rawOutputFilePtr);
	args->packet_list_tail->next_packet = saved_packet;
	args->packet_list_tail = saved_packet;
	args->captured_count++;
	remove_all_from_list(head);
	return;
}

void save_remaining_bytes(const int length, struct packet_structure* saved_packet, const unsigned char* remaining_bytes)
{
	saved_packet->remaining_length = length;
	saved_packet->remaining_bytes = (unsigned char*)malloc(length);
	memcpy(saved_packet->remaining_bytes, remaining_bytes, length);
}

void print_packet(const struct packet_structure* packet, FILE* outputFilePtr)
{
	// link layer
	print_ethernet_header(packet->ethernet_header, outputFilePtr);

	// network layer
	int network_type = packet->packet_type & NETWORK_LAYER_TYPE;
	if(network_type == IP_TYPE)
		print_ip_header((struct ip_hdr*)packet->network_layer_structure, outputFilePtr);
	
	// transport layer
	int transport_type = packet->packet_type & TRANSPORT_LAYER_TYPE;
	if(transport_type == TCP_TYPE)
		print_tcp_header((struct tcp_hdr*)packet->transport_layer_structure, outputFilePtr);
	else if(transport_type == UDP_TYPE)
		print_udp_header((struct udp_hdr*)packet->transport_layer_structure, outputFilePtr);
	
	// application layer
	int application_type = packet->packet_type & APPLICATION_LAYER_TYPE;
	if(application_type == DNS_QUERY_TYPE)
		print_dns_query((struct dns_query*)packet->application_layer_structure, outputFilePtr);
}
