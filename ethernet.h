#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
struct ether_hdr
{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];
    unsigned char ether_src_addr[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

bool get_ethernet_header(const unsigned char *ethernet_header_start, struct ether_hdr* destination_header);
void print_ethernet_header(const struct ether_hdr* ethernet_header, FILE* outputFilePtr);
