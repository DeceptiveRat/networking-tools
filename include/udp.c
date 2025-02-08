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

#include "ethernet.h"
#include "ip.h"
#include "udp.h"

int udpChecksumMatches(const unsigned char *packet_start, unsigned short *checksum)
{
	struct ip_hdr *ip_header = (struct ip_hdr *)(packet_start + ETHER_HDR_LEN);
	struct udp_hdr *udp_header =
		(struct udp_hdr *)(packet_start + ETHER_HDR_LEN + sizeof(struct ip_hdr));
	const unsigned char *data =
		packet_start + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);

	unsigned int sum = 0;
	sum += (ntohl(ip_header->ip_src_addr) >> 16) & 0xFFFF; // source addr
	sum += ntohl(ip_header->ip_src_addr) & 0xFFFF;
	sum += (ntohl(ip_header->ip_dest_addr) >> 16) & 0xFFFF; // dest addr
	sum += ntohl(ip_header->ip_dest_addr) & 0xFFFF;
	sum += 0x11; // protocol
	sum += ntohs(udp_header->udp_src_port);
	sum += ntohs(udp_header->udp_dest_port);
	sum += ntohs(udp_header->udp_length);
	sum += ntohs(udp_header->udp_length);

	int data_length_bytes = ntohs(udp_header->udp_length) - sizeof(struct udp_hdr);

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
	return (*checksum == ntohs(udp_header->udp_checksum)) ? 1 : 0;
}

int getUDPHeader(const unsigned char *packet_start, struct udp_hdr *destination_header)
{
	struct udp_hdr udp_header;
	udp_header = *(struct udp_hdr *)packet_start;
	udp_header.udp_src_port = ntohs(udp_header.udp_src_port);
	udp_header.udp_dest_port = ntohs(udp_header.udp_dest_port);
	udp_header.udp_length = ntohs(udp_header.udp_length);
	udp_header.udp_checksum = ntohs(udp_header.udp_checksum);

	*destination_header = udp_header;
	return 0;
}

void printUDPHeader(const struct udp_hdr *udp_header, FILE *outputFilePtr)
{
	fprintf(outputFilePtr, "\t\t[[  UDP Header  ]]\n");
	fprintf(outputFilePtr, "\t\t[ Src Port: %hu\t", udp_header->udp_src_port);
	fprintf(outputFilePtr, "Dest Port: %hu ]\n", udp_header->udp_dest_port);
	fprintf(outputFilePtr, "\t\t[ Length: %d\t", udp_header->udp_length);
	fprintf(outputFilePtr, "Checksum: %d ]\n", udp_header->udp_checksum);
}
