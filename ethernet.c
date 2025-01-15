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

#include "ethernet.h"

bool get_ethernet_header(const unsigned char *header_start, struct ether_hdr* destination_header)
{
    // ***IMPORTANT: change code to verify ethernet later***
    struct ether_hdr ethernet_header;
    ethernet_header = *(struct ether_hdr *)header_start;
	ethernet_header.ether_type = ntohs(ethernet_header.ether_type);

    *destination_header = ethernet_header;
    return true;
}

void print_ethernet_header(const struct ether_hdr* ethernet_header, FILE* outputFilePtr)
{
    fprintf(outputFilePtr, "[[  Ethernet Header  ]]\n");
    fprintf(outputFilePtr, "[ Source: %02x", ethernet_header->ether_src_addr[0]);

    for(int i = 1; i < ETHER_ADDR_LEN; i++)
        fprintf(outputFilePtr, ":%02x", ethernet_header->ether_src_addr[i]);

    fprintf(outputFilePtr, "\tDest: %02x", ethernet_header->ether_dest_addr[0]);

    for(int i = 1; i < ETHER_ADDR_LEN; i++)
        fprintf(outputFilePtr, ":%02x", ethernet_header->ether_dest_addr[i]);

	// TODO: change byte order later so it matches wireshark
    fprintf(outputFilePtr, "\tType: %hu(%x) ]\n", ethernet_header->ether_type, ethernet_header->ether_type);
}
