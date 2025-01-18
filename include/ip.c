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

#include <pcap.h>

#include "ip.h"

bool get_ip_header(const unsigned char *header_start, struct ip_hdr *destination_header)
{
	// ***IMPORTANT: change code to verify IP later***
	struct ip_hdr ip_header;
	ip_header = *(struct ip_hdr *)header_start;
	ip_header.ip_len = ntohs(ip_header.ip_len);
	ip_header.ip_id = ntohs(ip_header.ip_id);
	ip_header.ip_frag_offset = ntohs(ip_header.ip_frag_offset);
	ip_header.ip_checksum = ntohs(ip_header.ip_checksum);

	*destination_header = ip_header;
	return true;
}

void print_ip_header(const struct ip_hdr *ip_header, FILE *outputFilePtr)
{
	char addressString[IP_STRING_LEN];

	fprintf(outputFilePtr, "\t[[  IP Header  ]]\n");

	inet_ntop(AF_INET, (struct in_addr *)&(ip_header->ip_src_addr), addressString, IP_STRING_LEN);
	fprintf(outputFilePtr, "\t[ Source: %s\t", addressString);
	inet_ntop(AF_INET, (struct in_addr *)&(ip_header->ip_dest_addr), addressString, IP_STRING_LEN);
	fprintf(outputFilePtr, "Dest: %s ]\n", addressString);
	fprintf(outputFilePtr, "\t[ Type: %u\t", (unsigned int)(ip_header->ip_type));
	fprintf(outputFilePtr, "ID: %hu\tLength: %hu ]\n", ip_header->ip_id, ip_header->ip_len);
}
