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
