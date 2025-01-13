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
	const char functionName[] = "analyze_caught_packet";
	struct pcap_handler_arguments* args = *(struct pcap_handler_arguments**)user_args;
	FILE* outputFilePtr = args->outputFilePtr;

    struct allocated_pointers* head = NULL;
    head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));
    if(head == NULL)
        fatal("allocating memory for clean up head", functionName, NULL);
	head->next_pointer = NULL;
    struct allocated_pointers* tail = head;

	struct ethernet_packet* packet_structure;
	packet_structure = (struct ethernet_packet*)malloc(sizeof(struct ethernet_packet));
	if(packet_structure == NULL)
		fatal("allocating memory for packet_structure", functionName, outputFilePtr);
	add_new_pointer(head, &tail, packet_structure);
	memset(packet_structure, 0, sizeof(struct ethernet_packet));

    int tcp_header_length, total_header_size, pkt_data_len;
    unsigned char *pkt_data;

    fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

	// ============================ get link layer ===================================
    struct ether_hdr* ethernet_header = NULL;
    ethernet_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN);
    if(ethernet_header == NULL)
        fatal("allocating memory: ethernet_header", functionName, outputFilePtr);
	add_new_pointer(head, &tail, ethernet_header);

    // verify if it is ethernet later
    get_ethernet_header(packet, ethernet_header);
	packet_structure->packet_type = ETHERNET_PACKET;
	packet_structure->ethernet_header = ethernet_header;
    total_header_size = ETHER_HDR_LEN;

	// ============================ get network layer ===================================
    struct ip_hdr* ip_header = NULL;
    ip_header = (struct ip_hdr*)malloc(IP_HDR_LEN);
    if(ip_header == NULL)
        fatal("allocating memory: ip_header", functionName, outputFilePtr);
	add_new_pointer(head, &tail, ip_header);

    // verify if it is IP later
    get_ip_header(packet + total_header_size, ip_header);
	packet_structure->network_layer_structure = ip_header;
    total_header_size += IP_HDR_LEN;

	// ============================ get transport layer ===================================
    struct tcp_hdr* tcp_header = NULL;
    struct udp_hdr* udp_header = NULL;

    if(ip_header->ip_type == IP_TYPE_TCP)
    {
        if(tcp_checksum_matches(packet) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "TCP packet dropped.\n");
			free_all_pointers(head);
            return;
        }

        tcp_header = (struct tcp_hdr*)malloc(TCP_HDR_LEN);
        if(tcp_header == NULL)
            fatal("allocating memory: tcp_header", functionName, outputFilePtr);
		add_new_pointer(head, &tail, tcp_header);

        get_tcp_header(packet + total_header_size, tcp_header, &tcp_header_length);
		packet_structure->transport_layer_structure = tcp_header;
		packet_structure->packet_type = TCP_PACKET;
        total_header_size += tcp_header_length;
    }

    else if(ip_header->ip_type == IP_TYPE_UDP)
    {
        if(udp_checksum_matches(packet) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "UDP packet dropped.\n");
			free_all_pointers(head);
            return;
        }

        udp_header = (struct udp_hdr*)malloc(UDP_HDR_LEN);
        if(udp_header == NULL)
            fatal("allocating memory: udp_header", functionName, outputFilePtr);
		add_new_pointer(head, &tail, udp_header);

        get_udp_header(packet + total_header_size, udp_header);
		packet_structure->transport_layer_structure = udp_header;
		packet_structure->packet_type = UDP_PACKET;
        total_header_size += UDP_HDR_LEN;
    }

    else
    {
        fprintf(outputFilePtr, "unknown type\n");
		packet_structure->remaining_bytes = (unsigned char*)(packet + total_header_size);
		packet_structure->remaining_length = cap_header->len - total_header_size;
		packet_structure->next_packet = NULL;
		
		args->packet_list_tail->next_packet = packet_structure;
		args->packet_list_tail = packet_structure;
		args->captured_count++;

		remove_all_from_list(head);
		return;
    }

    pkt_data = (unsigned char *)(packet + total_header_size);
    pkt_data_len = cap_header->len - total_header_size;

	// ============================ get application layer ===================================
    struct dns_query* query_ptr = NULL;

	if(ip_header->ip_type == IP_TYPE_UDP)
	{
		bool result = true;
        result = get_dns_query(pkt_data, &query_ptr);
		// not dns query
		if(result == false)
		{
			packet_structure->remaining_bytes = (unsigned char*)(packet + total_header_size);
			packet_structure->remaining_length = cap_header->len - total_header_size;
			packet_structure->next_packet = NULL;
			
			args->packet_list_tail->next_packet = packet_structure;
			args->packet_list_tail = packet_structure;
			args->captured_count++;

			remove_all_from_list(head);
			return;
		}
		else
		{
			packet_structure->packet_type = DNS_QUERY_PACKET;
			packet_structure->application_layer_structure = query_ptr;
			packet_structure->remaining_bytes = NULL;
			packet_structure->remaining_length = 0;
			packet_structure->next_packet = NULL;
			
			args->packet_list_tail->next_packet = packet_structure;
			args->packet_list_tail = packet_structure;
			args->captured_count++;

			remove_all_from_list(head);
			return;
		}
	}

	packet_structure->remaining_bytes = (unsigned char*)(packet + total_header_size);
	packet_structure->remaining_length = cap_header->len - total_header_size;
	packet_structure->next_packet = NULL;
	
	args->packet_list_tail->next_packet = packet_structure;
	args->packet_list_tail = packet_structure;
	args->captured_count++;

	remove_all_from_list(head);
	return;
}
