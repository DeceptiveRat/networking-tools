#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define IP_HDR_LEN 20
#define IP_STRING_LEN 16
struct ip_hdr
{
    unsigned char ip_version_and_header_length;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_checksum;
    unsigned int ip_src_addr;
    unsigned int ip_dest_addr;
};
#define IP_TYPE_TCP 6
#define IP_TYPE_UDP 17

bool get_ip_header(const unsigned char *ip_header_start, struct ip_hdr* destination_header);
void print_ip_header(const struct ip_hdr* ip_header, FILE* outputFilePtr);
