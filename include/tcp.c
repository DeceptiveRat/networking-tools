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
#include <string.h>

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "otherFunctions.h"

int tcpChecksumMatches(const unsigned char *packet_start, unsigned short *checksum)
{
	struct ip_hdr *ip_header = (struct ip_hdr *)(packet_start + ETHER_HDR_LEN);
	struct tcp_hdr *tcp_header =
		(struct tcp_hdr *)(packet_start + ETHER_HDR_LEN + sizeof(struct ip_hdr));
	const unsigned char *data =
		packet_start + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);

	unsigned int sum = 0;
	sum += (ntohl(ip_header->ip_src_addr) >> 16) & 0xFFFF; // source addr
	sum += ntohl(ip_header->ip_src_addr) & 0xFFFF;
	sum += (ntohl(ip_header->ip_dest_addr) >> 16) & 0xFFFF; // dest addr
	sum += ntohl(ip_header->ip_dest_addr) & 0xFFFF;
	sum += 6; // protocol
	sum += ntohs(ip_header->ip_len) - sizeof(struct ip_hdr);

	sum += ntohs(tcp_header->tcp_src_port);
	sum += ntohs(tcp_header->tcp_dest_port);
	sum += (ntohl(tcp_header->tcp_seq) >> 16) & 0xFFFF;
	sum += ntohl(tcp_header->tcp_seq) & 0xFFFF;
	sum += (ntohl(tcp_header->tcp_ack) >> 16) & 0xFFFF; // dest port
	sum += ntohl(tcp_header->tcp_ack) & 0xFFFF;
	sum += ((short)(tcp_header->tcp_offset) << 12) | tcp_header->tcp_flags;
	sum += ntohs(tcp_header->tcp_window);
	sum += ntohs(tcp_header->tcp_urgent);

	// data + options
	int data_length_bytes =
		ntohs(ip_header->ip_len) - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr);

	for(int i = 0; i < data_length_bytes; i += 2)
	{
		unsigned short word = 0;
		word = data[i] << 8;

		if(i + 1 < data_length_bytes)
			word |= data[i + 1];

		sum += word;
	}

	while(sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	*checksum = (~sum) & 0xFFFF;
	return (*checksum == ntohs(tcp_header->tcp_checksum)) ? 1 : 0;
}

int getTCPHeader(const unsigned char *packet_start, const int data_offset, struct tcp_hdr *destination_header,
				 int *tcp_header_size)
{
	int status;

	unsigned short checksum;
	status = tcpChecksumMatches(packet_start, &checksum);
	if(status == -1)
	{
		return status;
	}
	else if(status == 0)
	{
		strcpy(error_message, "TCP checksum verification fail");
		return -1;
	}

	unsigned int header_size;
	struct tcp_hdr tcp_header;
	tcp_header = *(const struct tcp_hdr *)(packet_start + data_offset);
	header_size = 4 * tcp_header.tcp_offset;
	tcp_header.tcp_src_port = ntohs(tcp_header.tcp_src_port);
	tcp_header.tcp_dest_port = ntohs(tcp_header.tcp_dest_port);
	tcp_header.tcp_seq = ntohl(tcp_header.tcp_seq);
	tcp_header.tcp_ack = ntohl(tcp_header.tcp_ack);
	tcp_header.tcp_window = ntohs(tcp_header.tcp_window);
	tcp_header.tcp_checksum = ntohs(tcp_header.tcp_checksum);
	tcp_header.tcp_urgent = ntohs(tcp_header.tcp_urgent);

	*destination_header = tcp_header;
	*tcp_header_size = header_size;
	return 1;
}

void printTCPHeader(const struct tcp_hdr *tcp_header, FILE *outputFilePtr)
{
	int header_size = 4 * tcp_header->tcp_offset;

	fprintf(outputFilePtr, "\t\t[[  TCP Header  ]]\n");
	fprintf(outputFilePtr, "\t\t[ Src Port: %hu\t", tcp_header->tcp_src_port);
	fprintf(outputFilePtr, "Dest Port: %hu ]\n", tcp_header->tcp_dest_port);
	fprintf(outputFilePtr, "\t\t[ Seq #: %u\t", tcp_header->tcp_seq);
	fprintf(outputFilePtr, "Ack #: %u ]\n", tcp_header->tcp_ack);
	fprintf(outputFilePtr, "\t\t[ Header Size: %u\tFlags: ", header_size);

	if(tcp_header->tcp_flags & TCP_FIN)
		fprintf(outputFilePtr, "FIN ");

	if(tcp_header->tcp_flags & TCP_SYN)
		fprintf(outputFilePtr, "SYN ");

	if(tcp_header->tcp_flags & TCP_RST)
		fprintf(outputFilePtr, "RST ");

	if(tcp_header->tcp_flags & TCP_PUSH)
		fprintf(outputFilePtr, "PUSH ");

	if(tcp_header->tcp_flags & TCP_ACK)
		fprintf(outputFilePtr, "ACK ");

	if(tcp_header->tcp_flags & TCP_URG)
		fprintf(outputFilePtr, "URG ");

	fprintf(outputFilePtr, " ]\n");
}
