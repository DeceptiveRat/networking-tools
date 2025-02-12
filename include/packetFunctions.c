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

void saveCaughtPacket(unsigned char *user_args, const struct pcap_pkthdr *cap_header,
					  const unsigned char *packet)
{
	// initialize local variables
	const char function_name[] = "saveCaughtPacket";
	int status;

	int total_header_size = 0;
	int packet_length = cap_header->len;

	// use user arguments
	struct pcap_handler_arguments *args = *(struct pcap_handler_arguments **)user_args;
	FILE *output_file_ptr = args->output_file_ptr;
	FILE *raw_output_file_ptr = args->raw_output_file_ptr;

	struct packet_structure *structured_packet;
	structured_packet = (struct packet_structure *)malloc(sizeof(struct packet_structure));
	if(structured_packet == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	memset(structured_packet, 0, sizeof(struct packet_structure));

	fprintf(output_file_ptr, "[%d] Got a %d byte packet\n", args->captured_count, packet_length);

	// ============================ get link layer ===================================
	status =
		getLinkLayerHeader(&(structured_packet->packet_type),
						   &(structured_packet->link_layer_header), packet, args->captured_count,
						   output_file_ptr, raw_output_file_ptr, packet_length, &total_header_size);
	if(status == -1 || status == 0)
	{
		if(status == -1)
			printf("%s\n", error_message);
		saveRemainingBytes(packet_length - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));
		args->captured_count++;
		args->packet_list_tail->next_packet = structured_packet;
		args->packet_list_tail = structured_packet;
		return;
	}

	// ============================ get network layer ===================================
	status = getNetworkLayerHeader(&(structured_packet->packet_type),
								   &(structured_packet->network_layer_header), packet,
								   args->captured_count, output_file_ptr, raw_output_file_ptr,
								   packet_length, &total_header_size);
	if(status == -1 || status == 0)
	{
		if(status == -1)
			printf("%s\n", error_message);
		saveRemainingBytes(packet_length - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));
		args->captured_count++;
		args->packet_list_tail->next_packet = structured_packet;
		args->packet_list_tail = structured_packet;
		return;
	}

	// ============================ get transport layer ===================================

	status =
		getTransportLayerHeader(structured_packet, args, &total_header_size, packet, packet_length);
	if(status == -1 || status == 0)
	{
		if(status == -1)
			printf("%s\n", error_message);
		saveRemainingBytes(packet_length - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));
		args->captured_count++;
		args->packet_list_tail->next_packet = structured_packet;
		args->packet_list_tail = structured_packet;
		return;
	}

	// ============================ get application layer ===================================
	status = getApplicationLayerHeader(structured_packet, args, &total_header_size, packet,
									   packet_length);
	if(status == -1 || status == 0)
	{
		if(status == -1)
			printf("%s\n", error_message);
		saveRemainingBytes(packet_length - total_header_size, structured_packet,
						   (unsigned char *)(packet + total_header_size));
		args->captured_count++;
		args->packet_list_tail->next_packet = structured_packet;
		args->packet_list_tail = structured_packet;
		return;
	}

	structured_packet->remaining_bytes = NULL;
	structured_packet->remaining_length = 0;
	args->packet_list_tail->next_packet = structured_packet;
	args->packet_list_tail = structured_packet;
	return;
}

int saveRemainingBytes(const int length, struct packet_structure *structured_packet,
					   const unsigned char *remaining_bytes)
{
	structured_packet->remaining_length = length;
	structured_packet->remaining_bytes = (unsigned char *)malloc(length);
	memcpy(structured_packet->remaining_bytes, remaining_bytes, length);
	return 0;
}

int printPacket(const struct packet_structure *structured_packet, FILE *output_file_ptr)
{
	int packet_type = structured_packet->packet_type;
	// link layer
	if(packet_type & ETHERNET_TYPE)
		printEthernetHeader(structured_packet->link_layer_header, output_file_ptr);

	// network layer
	if(packet_type & IP_TYPE)
		printIPHeader(structured_packet->network_layer_header, output_file_ptr);

	// transport layer
	if(packet_type & TCP_TYPE)
		printTCPHeader(structured_packet->transport_layer_header, output_file_ptr);
	else if(packet_type & UDP_TYPE)
		printUDPHeader(structured_packet->transport_layer_header, output_file_ptr);

	// application layer
	if(packet_type & DNS_QUERY_TYPE)
		printDnsQuery(structured_packet->application_layer_header, output_file_ptr);

	if(structured_packet->remaining_length != 0)
	{
		fprintf(output_file_ptr, "printing remaining bytes\n");
		hex_stream_dump(structured_packet->remaining_bytes, structured_packet->remaining_length,
			 output_file_ptr);
	}

	return 0;
}

int getLinkLayerHeader(int *packet_type, void **link_layer_header_pp, const unsigned char *packet,
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

	status = getEthernetHeader(packet, ethernet_header);
	if(status == -1)
	{
		free(ethernet_header);
		return -1;
	}
	else if(status == 1)
	{
		*packet_type |= ETHERNET_TYPE;
		*link_layer_header_pp = ethernet_header;
		*total_header_size += ETHER_HDR_LEN;
		return 1;
	}

	// try other protocols

	free(ethernet_header);
	return 0;
}

int getNetworkLayerHeader(int *packet_type, void **network_layer_header_pp,
						  const unsigned char *packet, const int captured_count,
						  FILE *output_file_ptr, FILE *raw_output_file_ptr, const int packet_length,
						  int *total_header_size)
{
	const char function_name[] = "getNetworkLayerHeader";
	int status;

	if(!(*packet_type & ETHERNET_TYPE))
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

	status = getIPHeader(packet + *total_header_size, ip_header);
	if(status == -1)
	{
		free(ip_header);
		return -1;
	}
	else if(status == 1)
	{
		*packet_type |= IP_TYPE;
		*network_layer_header_pp = ip_header;
		*total_header_size += IP_HDR_LEN;
		return 1;
	}

	free(ip_header);
	return 0;
}

int getTransportLayerHeader(struct packet_structure *structured_packet,
							struct pcap_handler_arguments *args, int *total_header_size,
							const unsigned char *packet, const int packet_length)
{
	const char function_name[] = "getTransportLayerHeader";
	int status;

	if(!(structured_packet->packet_type & IP_TYPE))
	{
		perror(function_name);
		strcpy(error_message, "wrong network layer type");
		return -1;
	}

	void *transport_layer_header;

	if(((struct ip_hdr *)(structured_packet->network_layer_header))->ip_type == IP_TYPE_TCP)
	{
		transport_layer_header = malloc(TCP_HDR_LEN);
		if(transport_layer_header == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating memory");
			fatal(error_message, NULL, stdout);
		}

		int tcp_header_length;
		status =
			getTCPHeader(packet, *total_header_size, transport_layer_header, &tcp_header_length);
		if(status == 0)
		{
			strcpy(error_message, "IP header protocol field doesn't match actual transport layer protocol");
			free(transport_layer_header);
			return -1;
		}
		else if(status == -1)
		{
			free(transport_layer_header);
			return -1;
		}
		structured_packet->transport_layer_header = transport_layer_header;
		structured_packet->packet_type |= TCP_TYPE;
		*total_header_size += tcp_header_length;
	}
	else if(((struct ip_hdr *)(structured_packet->network_layer_header))->ip_type == IP_TYPE_UDP)
	{
		transport_layer_header = malloc(UDP_HDR_LEN);
		if(transport_layer_header == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating memory");
			fatal(error_message, NULL, stdout);
		}

		status = getUDPHeader(packet, *total_header_size, transport_layer_header);
		if(status == 0)
		{
			strcpy(error_message, "IP header protocol field doesn't match actual transport layer protocol");
			free(transport_layer_header);
			return -1;
		}
		else if(status == -1)
		{
			free(transport_layer_header);
			return -1;
		}

		structured_packet->transport_layer_header = transport_layer_header;
		structured_packet->packet_type |= UDP_TYPE;
		total_header_size += UDP_HDR_LEN;
	}
	else
		return 0;

	return 1;
}

int getApplicationLayerHeader(struct packet_structure *structured_packet,
							  struct pcap_handler_arguments *args, int *total_header_size,
							  const unsigned char *packet, const int packet_length)
{
	int status;

	if(structured_packet->packet_type & UDP_TYPE)
	{
		status = getDnsQuery((unsigned char *)(packet + *total_header_size),
							 (struct dns_query **)(&structured_packet->application_layer_header));
		if(status == 1)
		{
			structured_packet->packet_type |= DNS_QUERY_TYPE;
			return 1;
		}
		else if(status == -1)
			return -1;
	}

	// other protocols

	return 0;
}
